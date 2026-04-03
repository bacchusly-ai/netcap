// Package dispatch provides the ProtocolDispatcher stage that bridges
// reassembled TCP streams and raw UDP packets to protocol parsers, emitting
// parsed events to a downstream consumer (typically the Kafka producer).
package dispatch

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/netcap/netcap/internal/decode"
	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/internal/reassembly"
	"github.com/netcap/netcap/proto"
)

// Dispatcher reads reassembled TCP stream data and raw UDP decoded packets,
// resolves the appropriate protocol parser via the Registry, and forwards
// parsed ProtocolEvents to the output channel.
type Dispatcher struct {
	registry  *protocol.Registry
	tcpInput  <-chan reassembly.StreamData
	udpInput  <-chan decode.DecodedPacket
	output    chan<- *proto.ProtocolEvent
	logger    *slog.Logger
	wg        sync.WaitGroup
}

// New creates a Dispatcher.
//
//   - tcpInput delivers reassembled TCP stream chunks.
//   - udpInput delivers raw decoded UDP packets.
//   - output is typically the Kafka producer's input channel.
func New(
	registry *protocol.Registry,
	tcpInput <-chan reassembly.StreamData,
	udpInput <-chan decode.DecodedPacket,
	output chan<- *proto.ProtocolEvent,
	logger *slog.Logger,
) *Dispatcher {
	return &Dispatcher{
		registry: registry,
		tcpInput: tcpInput,
		udpInput: udpInput,
		output:   output,
		logger:   logger.With("stage", "dispatcher"),
	}
}

// Name returns the stage identifier.
func (d *Dispatcher) Name() string { return "protocol-dispatcher" }

// Start launches goroutines that consume TCP and UDP inputs.
func (d *Dispatcher) Start(ctx context.Context) error {
	d.wg.Add(2)
	go func() {
		defer d.wg.Done()
		d.tcpLoop(ctx)
	}()
	go func() {
		defer d.wg.Done()
		d.udpLoop(ctx)
	}()
	d.logger.Info("protocol dispatcher started")
	return nil
}

// Stop waits for both consumer goroutines to finish.
func (d *Dispatcher) Stop(_ context.Context) error {
	d.wg.Wait()
	d.logger.Info("protocol dispatcher stopped")
	return nil
}

// tcpLoop processes reassembled TCP stream data.
func (d *Dispatcher) tcpLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case sd, ok := <-d.tcpInput:
			if !ok {
				return
			}
			d.handleTCP(ctx, sd)
		}
	}
}

// udpLoop processes raw decoded UDP packets.
func (d *Dispatcher) udpLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-d.udpInput:
			if !ok {
				return
			}
			d.handleUDP(ctx, pkt)
		}
	}
}

// handleTCP resolves a parser for the reassembled TCP stream data and emits events.
func (d *Dispatcher) handleTCP(ctx context.Context, sd reassembly.StreamData) {
	if len(sd.Data) == 0 {
		return
	}

	p := d.registry.Resolve(sd.ConnMeta.SrcPort, sd.ConnMeta.DstPort, sd.Data, sd.IsClient)
	if p == nil {
		return
	}

	meta := protocol.ConnMeta{
		SrcIP:   net.ParseIP(sd.ConnMeta.SrcIP),
		DstIP:   net.ParseIP(sd.ConnMeta.DstIP),
		SrcPort: sd.ConnMeta.SrcPort,
		DstPort: sd.ConnMeta.DstPort,
	}

	events, err := p.Parse(sd.Data, meta, sd.IsClient)
	if err != nil {
		d.logger.Debug("parse error", "protocol", p.Name(), "err", err)
		return
	}

	for _, ev := range events {
		select {
		case d.output <- ev:
		case <-ctx.Done():
			return
		}
	}
}

// handleUDP resolves a parser for the raw UDP packet and emits events.
func (d *Dispatcher) handleUDP(ctx context.Context, pkt decode.DecodedPacket) {
	if len(pkt.Payload) == 0 {
		return
	}

	p := d.registry.Resolve(pkt.SrcPort, pkt.DstPort, pkt.Payload, true)
	if p == nil {
		return
	}

	meta := protocol.ConnMeta{
		SrcIP:   pkt.SrcIP,
		DstIP:   pkt.DstIP,
		SrcPort: pkt.SrcPort,
		DstPort: pkt.DstPort,
	}

	events, err := p.Parse(pkt.Payload, meta, true)
	if err != nil {
		d.logger.Debug("udp parse error", "protocol", p.Name(), "err", err)
		return
	}

	for _, ev := range events {
		select {
		case d.output <- ev:
		case <-ctx.Done():
			return
		}
	}
}
