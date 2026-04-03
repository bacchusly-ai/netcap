// Command netcap is the entry point for the network traffic capture agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netcap/netcap/internal/capture/afpacket"
	"github.com/netcap/netcap/internal/config"
	"github.com/netcap/netcap/internal/decode"
	"github.com/netcap/netcap/internal/dispatch"
	"github.com/netcap/netcap/internal/metrics"
	"github.com/netcap/netcap/internal/output"
	"github.com/netcap/netcap/internal/pipeline"
	"github.com/netcap/netcap/internal/protocol"
	protodns "github.com/netcap/netcap/internal/protocol/dns"
	protoftp "github.com/netcap/netcap/internal/protocol/ftp"
	protohttp "github.com/netcap/netcap/internal/protocol/http"
	protoimap "github.com/netcap/netcap/internal/protocol/imap"
	protomongodb "github.com/netcap/netcap/internal/protocol/mongodb"
	protomqtt "github.com/netcap/netcap/internal/protocol/mqtt"
	protomysql "github.com/netcap/netcap/internal/protocol/mysql"
	protopop3 "github.com/netcap/netcap/internal/protocol/pop3"
	protopostgres "github.com/netcap/netcap/internal/protocol/postgres"
	protoredis "github.com/netcap/netcap/internal/protocol/redis"
	protosmtp "github.com/netcap/netcap/internal/protocol/smtp"
	protossh "github.com/netcap/netcap/internal/protocol/ssh"
	prototls "github.com/netcap/netcap/internal/protocol/tls"
	protounknown "github.com/netcap/netcap/internal/protocol/unknown"
	protowebsocket "github.com/netcap/netcap/internal/protocol/websocket"
	"github.com/netcap/netcap/internal/reassembly"
)

func main() {
	configPath := flag.String("config", "configs/netcap.yaml", "path to configuration file")
	flag.Parse()

	// Set up structured JSON logger writing to stderr.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration.
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "path", *configPath, "err", err)
		os.Exit(1)
	}
	logger.Info("configuration loaded", "path", *configPath)

	// --- Build protocol registry ---
	registry := buildRegistry(cfg)
	logger.Info("protocol registry initialized", "parsers", len(cfg.Protocols.Enabled))

	// --- Build capture stage ---
	capturer := afpacket.New(afpacket.Config{
		Interface:     cfg.Capture.Interface,
		NumQueues:     cfg.Capture.NumQueues,
		BufferSizeMB:  cfg.Capture.BufferSize / (1024 * 1024), // config is in bytes
		SnapLength:    cfg.Capture.SnapLength,
		BPFFilter:     cfg.Capture.BPFFilter,
		FanoutType:    cfg.Capture.Fanout.Type,
		FanoutGroupID: cfg.Capture.Fanout.GroupID,
		OutputBuffer:  cfg.Decode.ChannelBuffer,
	}, logger)

	// Set up context with OS signal handling for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start capture to get the packet channel (capture has a non-standard Start).
	pktCh, err := capturer.Start(ctx)
	if err != nil {
		logger.Error("failed to start capture", "err", err)
		os.Exit(1)
	}
	logger.Info("capture started", "interface", cfg.Capture.Interface, "queues", cfg.Capture.NumQueues)

	// --- Build decoder ---
	decoder := decode.New(decode.DecoderConfig{
		Workers:       cfg.Decode.Workers,
		ChannelBuffer: cfg.Decode.ChannelBuffer,
	}, pktCh, logger)

	// --- Split decoder output: TCP → reassembly, UDP → dispatcher ---
	tcpCh := make(chan decode.DecodedPacket, cfg.Decode.ChannelBuffer)
	udpCh := make(chan decode.DecodedPacket, cfg.Decode.ChannelBuffer)
	splitter := &packetSplitter{
		input: decoder.Output(),
		tcp:   tcpCh,
		udp:   udpCh,
	}

	// --- Build reassembly ---
	reassembler := reassembly.New(reassembly.ReassemblyConfig{
		MaxBufferedPagesPerConn: cfg.Reassembly.MaxBufferedPagesPerConn,
		MaxBufferedPagesTotal:   cfg.Reassembly.MaxBufferedPagesTotal,
		ConnectionTimeout:       cfg.Reassembly.ConnectionTimeout,
		MaxConnectionAge:        cfg.Reassembly.MaxConnectionAge,
		FlushInterval:           cfg.Reassembly.FlushInterval,
		ChannelBuffer:           cfg.Decode.ChannelBuffer,
	}, tcpCh, logger)

	// --- Build Kafka producer ---
	kafkaProducer := output.NewProducer(output.KafkaConfig{
		Brokers:         cfg.Kafka.Brokers,
		Topic:           cfg.Kafka.Topic,
		BatchSize:       cfg.Kafka.BatchSize,
		BatchTimeout:    cfg.Kafka.BatchTimeout,
		Compression:     cfg.Kafka.Compression,
		RequiredAcks:    cfg.Kafka.RequiredAcks,
		NumWorkers:      cfg.Kafka.NumWorkers,
		MaxMessageBytes: cfg.Kafka.MaxMessageBytes,
	}, &output.JSONSerializer{}, cfg.Decode.ChannelBuffer, logger)

	// --- Build protocol dispatcher ---
	dispatcher := dispatch.New(
		registry,
		reassembler.Output(),
		udpCh,
		kafkaProducer.Input(),
		logger,
	)

	// --- Assemble pipeline ---
	p := pipeline.New(cfg, logger)

	// Stage 1: Decoder (capture is already started manually above)
	p.AddStage(decoder)
	// Stage 2: Packet splitter (TCP/UDP fan-out)
	p.AddStage(splitter)
	// Stage 3: TCP reassembly
	p.AddStage(reassembler)
	// Stage 4: Kafka producer
	p.AddStage(kafkaProducer)
	// Stage 5: Protocol dispatcher
	p.AddStage(dispatcher)

	// Optional: metrics server
	if cfg.Metrics.Enabled {
		metricsServer := metrics.NewServer(cfg.Metrics.Listen, cfg.Metrics.Path, logger)
		p.AddStage(metricsServer)
	}

	// Start the pipeline.
	if err := p.Run(ctx); err != nil {
		logger.Error("pipeline failed to start", "err", err)
		capturer.Close()
		os.Exit(1)
	}

	logger.Info("netcap running, press Ctrl+C to stop")

	// Block until a signal is received.
	<-ctx.Done()
	logger.Info("shutdown signal received")

	// Give stages a bounded amount of time to shut down.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := p.Shutdown(shutdownCtx); err != nil {
		logger.Error("pipeline shutdown error", "err", err)
	}
	if err := capturer.Close(); err != nil {
		logger.Error("capture close error", "err", err)
	}

	fmt.Fprintln(os.Stderr, "netcap stopped")
}

// buildRegistry creates and populates a protocol parser registry from config.
func buildRegistry(cfg *config.Config) *protocol.Registry {
	reg := protocol.NewRegistry()

	maxQ := cfg.Protocols.DB.MaxQueryLength

	// Register all parsers. Order does not matter — the registry uses
	// port-based lookup and DPI probing.
	reg.Register(&protohttp.Parser{})
	reg.Register(&protodns.Parser{})
	reg.Register(&prototls.Parser{})
	reg.Register(protomysql.NewParser(maxQ))
	reg.Register(protopostgres.NewParser(maxQ))
	reg.Register(protoredis.NewParser(maxQ))
	reg.Register(protomongodb.NewParser(maxQ))
	reg.Register(&protosmtp.Parser{})
	reg.Register(&protoftp.Parser{})
	reg.Register(&protoimap.Parser{})
	reg.Register(&protopop3.Parser{})
	reg.Register(&protomqtt.Parser{})
	reg.Register(&protowebsocket.Parser{})
	reg.Register(&protossh.Parser{})
	reg.Register(&protounknown.Parser{}) // fallback, must be last

	return reg
}

// packetSplitter is a pipeline stage that splits decoded packets into
// separate TCP and UDP channels for downstream consumers.
type packetSplitter struct {
	input <-chan decode.DecodedPacket
	tcp   chan decode.DecodedPacket
	udp   chan decode.DecodedPacket
	done  chan struct{}
}

func (s *packetSplitter) Name() string { return "packet-splitter" }

func (s *packetSplitter) Start(_ context.Context) error {
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		for pkt := range s.input {
			switch pkt.TransProto {
			case 6: // TCP
				s.tcp <- pkt
			case 17: // UDP
				s.udp <- pkt
			}
		}
		close(s.tcp)
		close(s.udp)
	}()
	return nil
}

func (s *packetSplitter) Stop(_ context.Context) error {
	if s.done != nil {
		<-s.done
	}
	return nil
}
