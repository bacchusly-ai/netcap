// Package imap implements a parser for the IMAP protocol.
package imap

import (
	"bytes"
	"strings"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// Parser decodes IMAP commands and responses.
type Parser struct{}

func NewParser() *Parser               { return &Parser{} }
func (p *Parser) Name() string         { return "imap" }
func (p *Parser) Ports() []uint16      { return []uint16{143, 993} }

// Probe returns a confidence score for IMAP traffic.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 4 {
		return 0
	}
	s := string(data[:min(len(data), 128)])
	upper := strings.ToUpper(s)

	// Server greeting.
	if strings.HasPrefix(s, "* OK") {
		return 90
	}
	// Tagged client command: e.g. "a001 LOGIN ..."
	for _, kw := range []string{" LOGIN ", " SELECT ", " FETCH ", " LIST ", " LOGOUT", " CAPABILITY", " SEARCH "} {
		if strings.Contains(upper, kw) {
			return 80
		}
	}
	// Untagged response.
	if strings.HasPrefix(s, "* ") {
		return 60
	}
	return 0
}

// Parse extracts IMAP command names from the data.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	var events []*proto.ProtocolEvent

	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		s := string(line)

		if isFromClient {
			// Client commands have the form: tag SP command SP args...
			ev := proto.NewEvent("imap", proto.DirectionRequest)
			fillMeta(ev, meta)
			parts := strings.SplitN(s, " ", 3)
			tag := ""
			cmd := s
			if len(parts) >= 2 {
				tag = parts[0]
				cmd = strings.ToUpper(parts[1])
			}
			ev.Metadata = map[string]string{"tag": tag, "command": cmd}
			events = append(events, ev)
		} else {
			ev := proto.NewEvent("imap", proto.DirectionResponse)
			fillMeta(ev, meta)
			ev.Metadata = map[string]string{"line": truncate(s, 256)}
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
