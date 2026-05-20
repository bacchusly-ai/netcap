// Package protocol defines the common interface and types for protocol parsers.
package protocol

import (
	"net"

	"github.com/netcap/netcap/proto"
)

// ConnMeta holds the connection 4-tuple for a captured segment.
//
// ConnID is a direction-agnostic identifier for the underlying TCP connection
// (zero for UDP). Parsers use it to maintain per-connection state across
// successive Parse calls — for example, to pair HTTP/1.x requests with their
// responses via a FIFO sequence counter.
type ConnMeta struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	ConnID  uint64
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

// ConnLifecycleHandler is an optional interface a Parser may implement to
// receive a notification when the underlying TCP connection has closed
// (either via FIN/RST or reassembly timeout). The reassembly stage emits
// the close event after all data for the connection has been delivered,
// so any per-connection state keyed by ConnID can be safely released here.
type ConnLifecycleHandler interface {
	OnConnClose(connID uint64)
}
