// Package pop3 implements a parser for the POP3 protocol.
package pop3

import (
	"bytes"
	"strings"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// Parser decodes POP3 commands and responses.
type Parser struct{}

func NewParser() *Parser               { return &Parser{} }
func (p *Parser) Name() string         { return "pop3" }
func (p *Parser) Ports() []uint16      { return []uint16{110, 995} }

// Probe returns a confidence score for POP3 traffic.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 3 {
		return 0
	}
	s := string(data[:min(len(data), 64)])
	for _, pfx := range []string{"+OK", "-ERR", "USER ", "PASS ", "RETR "} {
		if strings.HasPrefix(s, pfx) {
			return 90
		}
	}
	return 0
}

// Parse extracts POP3 commands and responses.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	var events []*proto.ProtocolEvent

	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		s := string(line)

		if isFromClient {
			ev := proto.NewEvent("pop3", proto.DirectionRequest)
			fillMeta(ev, meta)
			cmd := strings.ToUpper(s)
			if idx := strings.IndexByte(cmd, ' '); idx > 0 {
				cmd = cmd[:idx]
			}
			ev.Metadata = map[string]string{"command": cmd}
			events = append(events, ev)
		} else {
			ev := proto.NewEvent("pop3", proto.DirectionResponse)
			fillMeta(ev, meta)
			status := "OK"
			if strings.HasPrefix(s, "-ERR") {
				status = "ERR"
			}
			ev.Metadata = map[string]string{"status": status, "line": truncate(s, 256)}
			events = append(events, ev)
		}
	}
	return events, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func fillMeta(ev *proto.ProtocolEvent, meta protocol.ConnMeta) {
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ protocol.Parser = (*Parser)(nil)
