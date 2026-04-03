package reassembly

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

const (
	// maxBufferSize is the per-direction byte threshold that triggers an
	// automatic flush of the reassembled data to the output channel.
	maxBufferSize = 256 * 1024 // 256 KiB
)

// streamFactory creates biStream instances for the reassembly engine.
type streamFactory struct {
	output chan StreamData
	logger *slog.Logger
}

// New is called by the reassembly pool when a new TCP connection is observed.
func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow, _ *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	s := &biStream{
		net:       netFlow,
		transport: tcpFlow,
		output:    f.output,
		logger:    f.logger,
	}
	return s
}

// biStream tracks both directions of a single TCP connection.
type biStream struct {
	net       gopacket.Flow
	transport gopacket.Flow
	output    chan StreamData

	clientBuf bytes.Buffer
	serverBuf bytes.Buffer
	mu        sync.Mutex
	logger    *slog.Logger
}

// Accept decides whether to accept a TCP packet into the stream. We accept
// all packets and let the reassembly engine handle ordering.
func (s *biStream) Accept(
	_ *layers.TCP,
	_ gopacket.CaptureInfo,
	_ reassembly.TCPFlowDirection,
	_ reassembly.Sequence,
	start *bool,
	_ reassembly.AssemblerContext,
) bool {
	// Accept all packets; do not force a new stream.
	if start != nil {
		*start = false
	}
	return true
}

// ReassembledSG is called when the reassembly engine has ordered data ready.
func (s *biStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	if length == 0 {
		return
	}

	data := sg.Fetch(length)
	dir, _, _, _ := sg.Info()

	isClient := dir == reassembly.TCPDirClientToServer

	s.mu.Lock()
	defer s.mu.Unlock()

	buf := &s.serverBuf
	if isClient {
		buf = &s.clientBuf
	}
	buf.Write(data)

	// Flush if the buffer has grown past the threshold.
	if buf.Len() >= maxBufferSize {
		s.flushDirectionLocked(isClient, ac)
	}
}

// ReassemblyComplete is called when the TCP connection is closed or timed out.
// Returning false tells the engine we no longer need this stream.
func (s *biStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Flush any remaining data in both directions.
	if s.clientBuf.Len() > 0 {
		s.flushDirectionLocked(true, ac)
	}
	if s.serverBuf.Len() > 0 {
		s.flushDirectionLocked(false, ac)
	}

	// Return false = remove from pool (we are done).
	return false
}

// flushDirectionLocked sends buffered data for one direction to the output
// channel and resets the buffer. Caller must hold s.mu.
func (s *biStream) flushDirectionLocked(isClient bool, ac reassembly.AssemblerContext) {
	buf := &s.serverBuf
	if isClient {
		buf = &s.clientBuf
	}
	if buf.Len() == 0 {
		return
	}

	// Copy the data so the buffer can be reused.
	payload := make([]byte, buf.Len())
	copy(payload, buf.Bytes())
	buf.Reset()

	// Extract ports from the transport flow endpoints.
	srcPort, dstPort := extractPorts(s.transport)

	sd := StreamData{
		Net:       s.net,
		Transport: s.transport,
		Data:      payload,
		IsClient:  isClient,
		ConnMeta: ConnMeta{
			SrcIP:   s.net.Src().String(),
			DstIP:   s.net.Dst().String(),
			SrcPort: srcPort,
			DstPort: dstPort,
		},
	}

	if ac != nil {
		sd.Timestamp = ac.GetCaptureInfo().Timestamp
	}

	// Non-blocking send: if the consumer is slow we log and drop.
	select {
	case s.output <- sd:
	default:
		s.logger.Warn("stream output channel full, dropping reassembled data",
			"net", s.net, "transport", s.transport, "isClient", isClient, "bytes", len(payload))
	}
}

// extractPorts parses the source and destination ports from a transport-layer flow.
func extractPorts(f gopacket.Flow) (src, dst uint16) {
	if raw := f.Src().Raw(); len(raw) >= 2 {
		src = binary.BigEndian.Uint16(raw)
	}
	if raw := f.Dst().Raw(); len(raw) >= 2 {
		dst = binary.BigEndian.Uint16(raw)
	}
	return
}
