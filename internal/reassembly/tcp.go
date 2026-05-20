// Package reassembly provides TCP stream reassembly on top of gopacket's
// reassembly engine. It consumes DecodedPacket values from the decode stage
// and produces StreamData values for application-layer protocol parsers.
package reassembly

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"

	"github.com/netcap/netcap/internal/decode"
)

// StreamData represents a chunk of reassembled bytes from one direction
// of a TCP connection, or a connection-close marker when Closed is true.
//
// When Closed is true: Data is empty, IsClient is irrelevant, and ConnMeta
// (in particular ConnID) identifies the connection that just ended. The
// marker is emitted after any pending data for the connection has already
// been flushed downstream, so parsers can safely drop per-connection state.
type StreamData struct {
	Net       gopacket.Flow
	Transport gopacket.Flow
	Data      []byte
	IsClient  bool // true for the initiating (client -> server) direction
	Timestamp time.Time
	ConnMeta  ConnMeta
	Closed    bool
}

// ConnMeta carries the original four-tuple plus a stable connection
// identifier for the bidirectional TCP stream. ConnID is computed via
// gopacket's direction-agnostic FastHash so both directions of the same
// connection share the same value — protocol parsers rely on this to
// correlate requests with their responses.
type ConnMeta struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	ConnID  uint64
}

// ReassemblyConfig controls the reassembly engine.
type ReassemblyConfig struct {
	MaxBufferedPagesPerConn int
	MaxBufferedPagesTotal   int
	ConnectionTimeout       time.Duration
	MaxConnectionAge        time.Duration
	FlushInterval           time.Duration
	ChannelBuffer           int
}

// TCPReassembler is a pipeline stage that reassembles TCP streams.
type TCPReassembler struct {
	cfg       ReassemblyConfig
	input     <-chan decode.DecodedPacket
	output    chan StreamData
	pool      *reassembly.StreamPool
	assembler *reassembly.Assembler
	logger    *slog.Logger
	wg        sync.WaitGroup
	mu        sync.Mutex
}

// New creates a TCPReassembler. Call Start to begin processing.
func New(cfg ReassemblyConfig, input <-chan decode.DecodedPacket, logger *slog.Logger) *TCPReassembler {
	if cfg.ChannelBuffer <= 0 {
		cfg.ChannelBuffer = 4096
	}
	output := make(chan StreamData, cfg.ChannelBuffer)

	factory := &streamFactory{
		output: output,
		logger: logger.With("component", "stream-factory"),
	}
	pool := reassembly.NewStreamPool(factory)
	assembler := reassembly.NewAssembler(pool)

	if cfg.MaxBufferedPagesTotal > 0 {
		assembler.MaxBufferedPagesTotal = cfg.MaxBufferedPagesTotal
	}
	if cfg.MaxBufferedPagesPerConn > 0 {
		assembler.MaxBufferedPagesPerConnection = cfg.MaxBufferedPagesPerConn
	}

	return &TCPReassembler{
		cfg:       cfg,
		input:     input,
		output:    output,
		pool:      pool,
		assembler: assembler,
		logger:    logger.With("stage", "tcp-reassembly"),
	}
}

// Output returns the channel delivering reassembled stream data.
func (r *TCPReassembler) Output() <-chan StreamData { return r.output }

// Start launches the reassembly goroutine and periodic flush ticker.
func (r *TCPReassembler) Start(ctx context.Context) error {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run(ctx)
	}()
	return nil
}

// Stop waits for the reassembly goroutine to finish and closes the output.
func (r *TCPReassembler) Stop(_ context.Context) error {
	r.wg.Wait()
	// Flush remaining connections.
	r.mu.Lock()
	r.assembler.FlushAll()
	r.mu.Unlock()
	close(r.output)
	return nil
}

// Name returns the stage identifier.
func (r *TCPReassembler) Name() string { return "tcp-reassembly" }

// run is the main loop that feeds TCP packets into the assembler and
// periodically flushes stale connections.
func (r *TCPReassembler) run(ctx context.Context) {
	flushInterval := r.cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 30 * time.Second
	}
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case pkt, ok := <-r.input:
			if !ok {
				return
			}
			if pkt.TCP == nil {
				// Non-TCP packets are ignored by the reassembler.
				continue
			}
			r.feedPacket(pkt)

		case <-ticker.C:
			r.flushOlderThan(r.cfg.ConnectionTimeout)
		}
	}
}

// feedPacket assembles a single TCP packet. It must compute the network
// flow from the decoded IP addresses so the assembler can track connections.
func (r *TCPReassembler) feedPacket(pkt decode.DecodedPacket) {
	tcp := pkt.TCP

	// Build capture-info to satisfy the assembler context requirement.
	ci := gopacket.CaptureInfo{
		Timestamp:     pkt.Timestamp,
		CaptureLength: len(pkt.RawPacket),
		Length:        len(pkt.RawPacket),
	}

	ac := &assemblerCtx{ci: ci}

	// Construct a flow from IP endpoints so the assembler can key connections.
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, pkt.SrcIP, pkt.DstIP)

	r.mu.Lock()
	r.assembler.AssembleWithContext(netFlow, tcp, ac)
	r.mu.Unlock()
}

// flushOlderThan removes connections that have been idle for at least d.
func (r *TCPReassembler) flushOlderThan(d time.Duration) {
	r.mu.Lock()
	flushed, closed := r.assembler.FlushCloseOlderThan(time.Now().Add(-d))
	r.mu.Unlock()
	if flushed > 0 || closed > 0 {
		r.logger.Debug("flushed stale connections", "flushed", flushed, "closed", closed)
	}
}

// assemblerCtx carries gopacket.CaptureInfo through the reassembly engine.
type assemblerCtx struct {
	ci gopacket.CaptureInfo
}

func (a *assemblerCtx) GetCaptureInfo() gopacket.CaptureInfo { return a.ci }
