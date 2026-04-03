// Package protocol defines the common interface and types for protocol parsers.
package protocol

import (
	"net"

	"github.com/netcap/netcap/proto"
)

// ConnMeta holds the connection 4-tuple for a captured segment.
type ConnMeta struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
}

// Parser is the interface every protocol-specific parser must implement.
type Parser interface {
	// Name returns the human-readable protocol name (e.g. "mysql").
	Name() string
	// Ports returns the well-known ports associated with this protocol.
	Ports() []uint16
	// Probe inspects the first bytes of a stream and returns a confidence
	// score (0-100) that the data belongs to this protocol.
	Probe(data []byte, isFromClient bool) int
	// Parse decodes the payload and returns zero or more ProtocolEvents.
	Parse(data []byte, meta ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error)
}
