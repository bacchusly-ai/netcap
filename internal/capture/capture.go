// Package capture defines the core packet capture abstractions.
package capture

import (
	"context"
	"time"
)

// Packet represents a single captured network packet.
type Packet struct {
	Data       []byte
	Timestamp  time.Time
	CaptureLen int
	OrigLen    int
}

// Stats holds packet capture statistics.
type Stats struct {
	PacketsReceived  uint64
	PacketsDropped   uint64
	PacketsIfDropped uint64
}

// Capturer is the interface that all capture backends must implement.
type Capturer interface {
	// Name returns the human-readable name of this capture backend.
	Name() string
	// Start begins packet capture and returns a channel that delivers packets.
	// The capture runs until the context is cancelled.
	Start(ctx context.Context) (<-chan Packet, error)
	// Stats returns the current capture statistics.
	Stats() Stats
	// Close releases all resources held by the capturer.
	Close() error
}
