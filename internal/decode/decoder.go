// Package decode provides zero-allocation packet decoding using gopacket's
// DecodingLayerParser. It reads raw packets from a capture channel, extracts
// network/transport layer fields, and forwards DecodedPacket values downstream.
package decode

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/netcap/netcap/internal/capture"
)

// DecodedPacket holds the parsed fields extracted from a raw packet.
type DecodedPacket struct {
	Timestamp  time.Time
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	TransProto uint8 // 6 = TCP, 17 = UDP
	TCPFlags   TCPFlags
	Payload    []byte

	// TCP is non-nil only for TCP packets; used by the reassembly stage.
	TCP *layers.TCP
	// RawPacket is the original captured byte slice.
	RawPacket []byte
}

// TCPFlags mirrors the most commonly inspected TCP control bits.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
}

// DecoderConfig controls the decode stage behaviour.
type DecoderConfig struct {
	Workers       int
	ChannelBuffer int
}

// Decoder is a pipeline stage that decodes raw packets in parallel.
type Decoder struct {
	cfg    DecoderConfig
	input  <-chan capture.Packet
	output chan DecodedPacket
	logger *slog.Logger
	wg     sync.WaitGroup
}

// New creates a Decoder. The caller must call Start to begin processing.
func New(cfg DecoderConfig, input <-chan capture.Packet, logger *slog.Logger) *Decoder {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.ChannelBuffer <= 0 {
		cfg.ChannelBuffer = 4096
	}
	return &Decoder{
		cfg:    cfg,
		input:  input,
		output: make(chan DecodedPacket, cfg.ChannelBuffer),
		logger: logger.With("stage", "decoder"),
	}
}

// Output returns the channel that delivers decoded packets.
func (d *Decoder) Output() <-chan DecodedPacket { return d.output }

// Start launches the configured number of decode workers.
func (d *Decoder) Start(ctx context.Context) error {
	for i := range d.cfg.Workers {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.decodeWorker(ctx)
		}()
		d.logger.Debug("started decode worker", "worker", i)
	}
	return nil
}

// Stop waits for all workers to drain and closes the output channel.
func (d *Decoder) Stop(_ context.Context) error {
	d.wg.Wait()
	close(d.output)
	return nil
}

// Name returns the stage identifier.
func (d *Decoder) Name() string { return "decoder" }

// decodeWorker runs in its own goroutine. Each worker pre-allocates layer
// variables so that DecodingLayerParser can decode without heap allocation
// on the hot path.
func (d *Decoder) decodeWorker(ctx context.Context) {
	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		tcp     layers.TCP
		udp     layers.UDP
		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth, &ip4, &ip6, &tcp, &udp, &payload,
	)
	parser.IgnoreUnsupported = true

	decoded := make([]gopacket.LayerType, 0, 6)

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-d.input:
			if !ok {
				return
			}
			if err := parser.DecodeLayers(pkt.Data, &decoded); err != nil {
				d.logger.Debug("decode error", "err", err)
				continue
			}

			dp := DecodedPacket{
				Timestamp: pkt.Timestamp,
				RawPacket: pkt.Data,
			}

			var hasIP, hasTransport bool

			for _, lt := range decoded {
				switch lt {
				case layers.LayerTypeIPv4:
					dp.SrcIP = ip4.SrcIP
					dp.DstIP = ip4.DstIP
					hasIP = true

				case layers.LayerTypeIPv6:
					dp.SrcIP = ip6.SrcIP
					dp.DstIP = ip6.DstIP
					hasIP = true

				case layers.LayerTypeTCP:
					dp.SrcPort = uint16(tcp.SrcPort)
					dp.DstPort = uint16(tcp.DstPort)
					dp.TransProto = 6
					dp.TCPFlags = TCPFlags{
						SYN: tcp.SYN,
						ACK: tcp.ACK,
						FIN: tcp.FIN,
						RST: tcp.RST,
						PSH: tcp.PSH,
					}
					// Keep a reference for the reassembly stage. We copy the
					// TCP header struct so the pre-allocated variable can be
					// reused on the next iteration.
					tcpCopy := tcp
					dp.TCP = &tcpCopy
					dp.Payload = tcp.Payload
					hasTransport = true

				case layers.LayerTypeUDP:
					dp.SrcPort = uint16(udp.SrcPort)
					dp.DstPort = uint16(udp.DstPort)
					dp.TransProto = 17
					dp.Payload = udp.Payload
					hasTransport = true

				case gopacket.LayerTypePayload:
					if dp.Payload == nil {
						dp.Payload = payload.Payload()
					}
				}
			}

			// Only forward packets that have at least an IP and transport header.
			if !hasIP || !hasTransport {
				continue
			}

			select {
			case d.output <- dp:
			case <-ctx.Done():
				return
			}
		}
	}
}

// compile-time check that Decoder satisfies pipeline.Stage-like interface.
var _ fmt.Stringer = (*Decoder)(nil)

func (d *Decoder) String() string { return d.Name() }
