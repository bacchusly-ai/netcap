package output

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"

	"github.com/netcap/netcap/proto"
)

// KafkaConfig holds the configuration for the Kafka producer.
type KafkaConfig struct {
	Brokers         []string      `json:"brokers"`
	Topic           string        `json:"topic"`
	BatchSize       int           `json:"batch_size"`
	BatchTimeout    time.Duration `json:"batch_timeout"`
	Compression     string        `json:"compression"`      // "lz4", "snappy", "gzip", or "" for none
	RequiredAcks    int           `json:"required_acks"`     // -1 = all, 0 = none, 1 = leader
	NumWorkers      int           `json:"num_workers"`
	MaxMessageBytes int           `json:"max_message_bytes"`
}

// Producer fans out ProtocolEvents to Kafka via multiple writer goroutines.
type Producer struct {
	cfg        KafkaConfig
	writers    []*kafka.Writer
	input      chan *proto.ProtocolEvent
	serializer Serializer
	logger     *slog.Logger
	wg         sync.WaitGroup
}

// NewProducer creates a new Producer. inputSize controls the channel buffer.
func NewProducer(cfg KafkaConfig, serializer Serializer, inputSize int, logger *slog.Logger) *Producer {
	if cfg.NumWorkers <= 0 {
		cfg.NumWorkers = 1
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 500 * time.Millisecond
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = 1 << 20 // 1 MiB
	}
	if cfg.RequiredAcks == 0 {
		cfg.RequiredAcks = 1
	}
	if logger == nil {
		logger = slog.Default()
	}

	writers := make([]*kafka.Writer, cfg.NumWorkers)
	for i := range writers {
		w := &kafka.Writer{
			Addr:         kafka.TCP(cfg.Brokers...),
			Topic:        cfg.Topic,
			Balancer:     &kafka.ReferenceHash{},
			Async:        true,
			BatchSize:    cfg.BatchSize,
			BatchTimeout: cfg.BatchTimeout,
			MaxAttempts:  3,
			RequiredAcks: kafka.RequiredAcks(cfg.RequiredAcks),
		}
		w.Compression = compressionCodec(cfg.Compression)
		writers[i] = w
	}

	return &Producer{
		cfg:        cfg,
		writers:    writers,
		input:      make(chan *proto.ProtocolEvent, inputSize),
		serializer: serializer,
		logger:     logger,
	}
}

// Input returns the send-only channel callers should push events into.
func (p *Producer) Input() chan<- *proto.ProtocolEvent {
	return p.input
}

// Start launches NumWorkers goroutines that drain the input channel and
// write batches to Kafka. It blocks until ctx is cancelled.
func (p *Producer) Start(ctx context.Context) error {
	for i := 0; i < p.cfg.NumWorkers; i++ {
		idx := i
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.worker(ctx, idx)
		}()
	}
	p.logger.Info("kafka producer started", "workers", p.cfg.NumWorkers, "topic", p.cfg.Topic)
	return nil
}

// Stop gracefully shuts down the producer: it closes the input channel,
// waits for all workers to finish, and then closes every Kafka writer.
func (p *Producer) Stop(_ context.Context) error {
	close(p.input)
	p.wg.Wait()

	var firstErr error
	for _, w := range p.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	p.logger.Info("kafka producer stopped")
	return firstErr
}

// Name returns a human-readable name for this component.
func (p *Producer) Name() string {
	return "kafka-producer"
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

func (p *Producer) worker(ctx context.Context, idx int) {
	w := p.writers[idx]
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-p.input:
			if !ok {
				return
			}
			data, err := p.serializer.Marshal(ev)
			if err != nil {
				p.logger.Error("serialize failed", "err", err)
				continue
			}
			key := flowKey(ev)
			msg := kafka.Message{
				Key:   key,
				Value: data,
			}
			if err := w.WriteMessages(ctx, msg); err != nil {
				p.logger.Error("kafka write failed", "err", err, "worker", idx)
			}
		}
	}
}

// flowKey produces a deterministic 8-byte key from the 5-tuple so that
// messages belonging to the same flow always land on the same partition.
func flowKey(ev *proto.ProtocolEvent) []byte {
	h := fnv.New64a()
	_, _ = h.Write(ev.SrcIP)
	_, _ = h.Write(ev.DstIP)
	portBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(portBuf, ev.SrcPort)
	_, _ = h.Write(portBuf)
	binary.BigEndian.PutUint32(portBuf, ev.DstPort)
	_, _ = h.Write(portBuf)
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, h.Sum64())
	return out
}

// compressionCodec maps a config string to a kafka.Compression value.
func compressionCodec(name string) kafka.Compression {
	switch name {
	case "lz4":
		return kafka.Lz4
	case "snappy":
		return kafka.Snappy
	case "gzip":
		return kafka.Gzip
	default:
		return 0 // no compression
	}
}

// FlowKey is exported for testing only.
func FlowKey(ev *proto.ProtocolEvent) []byte {
	return flowKey(ev)
}

// Compile-time check that Name returns a non-empty string.
var _ = func() string { p := &Producer{}; return p.Name() }
