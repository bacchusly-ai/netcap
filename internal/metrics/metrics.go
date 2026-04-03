// Package metrics defines Prometheus metrics for the netcap pipeline.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "netcap"

var (
	// PacketsCaptured counts packets received per capture queue.
	PacketsCaptured = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "packets_captured_total",
		Help:      "Total number of packets captured.",
	}, []string{"queue"})

	// PacketsDropped counts packets dropped per queue and reason.
	PacketsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "packets_dropped_total",
		Help:      "Total number of packets dropped.",
	}, []string{"queue", "reason"})

	// CaptureBytes counts bytes captured per queue.
	CaptureBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "capture_bytes_total",
		Help:      "Total bytes captured.",
	}, []string{"queue"})

	// DecodeLatency observes per-packet decode latency in seconds.
	// Exponential buckets from 1us (1e-6) to 1s with factor 10 (7 buckets).
	DecodeLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "decode_latency_seconds",
		Help:      "Packet decode latency in seconds.",
		Buckets:   prometheus.ExponentialBuckets(1e-6, 10, 7), // 1us -> 1s
	})

	// ActiveStreams tracks the current number of active TCP streams.
	ActiveStreams = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "active_streams",
		Help:      "Current number of active TCP reassembly streams.",
	})

	// ReassemblyPagesUsed tracks page-buffer usage in the reassembly engine.
	ReassemblyPagesUsed = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "reassembly_pages_used",
		Help:      "Number of reassembly page buffers currently in use.",
	})

	// ProtocolEvents counts parsed protocol events by protocol and direction.
	ProtocolEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "protocol_events_total",
		Help:      "Total parsed protocol-level events.",
	}, []string{"protocol", "direction"})

	// ParseErrors counts protocol parse errors by protocol and error type.
	ParseErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "parse_errors_total",
		Help:      "Total protocol parse errors.",
	}, []string{"protocol", "error_type"})

	// KafkaMessagesSent counts messages successfully sent to Kafka.
	KafkaMessagesSent = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "kafka_messages_sent_total",
		Help:      "Total messages sent to Kafka.",
	})

	// KafkaSendErrors counts Kafka send failures.
	KafkaSendErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "kafka_send_errors_total",
		Help:      "Total Kafka send errors.",
	})

	// KafkaBatchLatency observes Kafka batch write latency in seconds.
	KafkaBatchLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "kafka_batch_latency_seconds",
		Help:      "Kafka batch write latency in seconds.",
		Buckets:   prometheus.DefBuckets,
	})

	// ChannelUtilization tracks pipeline channel fill ratio per stage (0-1).
	ChannelUtilization = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "channel_utilization_ratio",
		Help:      "Pipeline channel utilization ratio (0-1) per stage.",
	}, []string{"stage"})
)
