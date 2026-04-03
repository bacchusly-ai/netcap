// Package config provides configuration loading and validation for netcap.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level configuration for netcap.
type Config struct {
	Capture    CaptureConfig    `mapstructure:"capture"`
	Decode     DecodeConfig     `mapstructure:"decode"`
	Reassembly ReassemblyConfig `mapstructure:"reassembly"`
	Protocols  ProtocolsConfig  `mapstructure:"protocols"`
	Kafka      KafkaConfig      `mapstructure:"kafka"`
	Metrics    MetricsConfig    `mapstructure:"metrics"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	Runtime    RuntimeConfig    `mapstructure:"runtime"`
}

// CaptureConfig controls the packet capture layer.
type CaptureConfig struct {
	Interface  string       `mapstructure:"interface"`
	Mode       string       `mapstructure:"mode"`
	NumQueues  int          `mapstructure:"num_queues"`
	BufferSize int          `mapstructure:"buffer_size"`
	SnapLength int          `mapstructure:"snap_length"`
	BPFFilter  string       `mapstructure:"bpf_filter"`
	Fanout     FanoutConfig `mapstructure:"fanout"`
}

// FanoutConfig controls AF_PACKET fanout settings.
type FanoutConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	GroupID int    `mapstructure:"group_id"`
	Type    string `mapstructure:"type"`
	Size    int    `mapstructure:"size"`
}

// DecodeConfig controls packet decoding workers.
type DecodeConfig struct {
	Workers       int `mapstructure:"workers"`
	ChannelBuffer int `mapstructure:"channel_buffer"`
}

// ReassemblyConfig controls TCP stream reassembly.
type ReassemblyConfig struct {
	MaxBufferedPagesPerConn int           `mapstructure:"max_buffered_pages_per_conn"`
	MaxBufferedPagesTotal   int           `mapstructure:"max_buffered_pages_total"`
	ConnectionTimeout       time.Duration `mapstructure:"connection_timeout"`
	MaxConnectionAge        time.Duration `mapstructure:"max_connection_age"`
	FlushInterval           time.Duration `mapstructure:"flush_interval"`
}

// ProtocolsConfig controls which application-layer protocols are parsed.
type ProtocolsConfig struct {
	Enabled []string   `mapstructure:"enabled"`
	HTTP    HTTPConfig `mapstructure:"http"`
	TLS     TLSConfig  `mapstructure:"tls"`
	DB      DBConfig   `mapstructure:"db"`
}

// HTTPConfig holds HTTP-specific parsing options.
type HTTPConfig struct {
	MaxBodyCapture int  `mapstructure:"max_body_capture"`
	CaptureHeaders bool `mapstructure:"capture_headers"`
}

// TLSConfig holds TLS-specific parsing options.
type TLSConfig struct {
	ExtractJA3          bool `mapstructure:"extract_ja3"`
	ExtractCertificates bool `mapstructure:"extract_certificates"`
}

// DBConfig holds database protocol parsing options.
type DBConfig struct {
	MaxQueryLength int `mapstructure:"max_query_length"`
}

// KafkaConfig controls the Kafka producer.
type KafkaConfig struct {
	Brokers         []string      `mapstructure:"brokers"`
	Topic           string        `mapstructure:"topic"`
	BatchSize       int           `mapstructure:"batch_size"`
	BatchTimeout    time.Duration `mapstructure:"batch_timeout"`
	Compression     string        `mapstructure:"compression"`
	RequiredAcks    int           `mapstructure:"required_acks"`
	NumWorkers      int           `mapstructure:"num_workers"`
	MaxMessageBytes int           `mapstructure:"max_message_bytes"`
}

// MetricsConfig controls the Prometheus metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"`
	Path    string `mapstructure:"path"`
}

// LoggingConfig controls structured logging.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// RuntimeConfig controls Go runtime tuning.
type RuntimeConfig struct {
	GOMAXPROCS int `mapstructure:"gomaxprocs"`
}

// Defaults returns a Config populated with sensible default values.
func Defaults() *Config {
	return &Config{
		Capture: CaptureConfig{
			Interface:  "eth0",
			Mode:       "afpacket",
			NumQueues:  1,
			BufferSize: 4 * 1024 * 1024, // 4 MiB
			SnapLength: 9000,
			Fanout: FanoutConfig{
				Enabled: false,
				GroupID: 1,
				Type:    "hash",
				Size:    4,
			},
		},
		Decode: DecodeConfig{
			Workers:       4,
			ChannelBuffer: 4096,
		},
		Reassembly: ReassemblyConfig{
			MaxBufferedPagesPerConn: 256,
			MaxBufferedPagesTotal:   65536,
			ConnectionTimeout:       2 * time.Minute,
			MaxConnectionAge:        10 * time.Minute,
			FlushInterval:           30 * time.Second,
		},
		Protocols: ProtocolsConfig{
			Enabled: []string{"http", "dns", "tls"},
			HTTP: HTTPConfig{
				MaxBodyCapture: 65536,
				CaptureHeaders: true,
			},
			TLS: TLSConfig{
				ExtractJA3:          true,
				ExtractCertificates: false,
			},
			DB: DBConfig{
				MaxQueryLength: 4096,
			},
		},
		Kafka: KafkaConfig{
			Brokers:         []string{"localhost:9092"},
			Topic:           "netcap-events",
			BatchSize:       100,
			BatchTimeout:    500 * time.Millisecond,
			Compression:     "lz4",
			RequiredAcks:    1,
			NumWorkers:      2,
			MaxMessageBytes: 1 << 20,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Listen:  ":9090",
			Path:    "/metrics",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stderr",
		},
		Runtime: RuntimeConfig{
			GOMAXPROCS: 0, // 0 means use runtime default
		},
	}
}

// Load reads a YAML configuration file and returns a Config.
// Missing keys fall back to Defaults().
func Load(path string) (*Config, error) {
	cfg := Defaults()

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// Validate checks that required fields are set and values are within
// acceptable ranges.
func (c *Config) Validate() error {
	var errs []string

	if c.Capture.Interface == "" {
		errs = append(errs, "capture.interface is required")
	}
	if c.Capture.SnapLength <= 0 {
		errs = append(errs, "capture.snap_length must be positive")
	}
	if c.Decode.Workers <= 0 {
		errs = append(errs, "decode.workers must be positive")
	}
	if len(c.Kafka.Brokers) == 0 {
		errs = append(errs, "kafka.brokers must not be empty")
	}
	if c.Kafka.Topic == "" {
		errs = append(errs, "kafka.topic is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}
	return nil
}
