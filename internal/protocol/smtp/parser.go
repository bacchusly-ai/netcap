// Package smtp implements a parser for the SMTP protocol.
package smtp

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// Known SMTP command prefixes (client-side).
var smtpCommands = []string{"EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:", "DATA", "QUIT", "RSET", "NOOP", "AUTH "}

// Parser decodes SMTP command/response exchanges.
type Parser struct{}

func NewParser() *Parser               { return &Parser{} }
func (p *Parser) Name() string         { return "smtp" }
func (p *Parser) Ports() []uint16      { return []uint16{25, 587} }

// Probe returns a confidence score for SMTP traffic.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 4 {
		return 0
	}
	s := string(data[:min(len(data), 128)])
	for _, prefix := range []string{"220 ", "EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:"} {
		if strings.HasPrefix(s, prefix) {
			return 90
		}
	}
	// Check for 3-digit response code at start.
	if len(data) >= 4 && data[3] == ' ' || (len(data) >= 4 && data[3] == '-') {
		if _, err := strconv.Atoi(string(data[:3])); err == nil {
			return 60
		}
	}
	return 0
}

// Parse extracts SMTP commands and response codes.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	var events []*proto.ProtocolEvent

	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		s := string(line)

		if isFromClient {
			ev := proto.NewEvent("smtp", proto.DirectionRequest)
			fillMeta(ev, meta)
			cmd := extractCommand(s)
			ev.Metadata = map[string]string{"command": cmd, "line": s}
			events = append(events, ev)
		} else {
			// Server response: 3-digit code + space/dash + text.
			if len(s) >= 3 {
				if code, err := strconv.Atoi(s[:3]); err == nil {
					ev := proto.NewEvent("smtp", proto.DirectionResponse)
					fillMeta(ev, meta)
					msg := ""
					if len(s) > 4 {
						msg = s[4:]
					}
					ev.Metadata = map[string]string{
						"code":    strconv.Itoa(code),
						"message": msg,
					}
					events = append(events, ev)
				}
			}
		}
	}
	return events, nil
}

// extractCommand returns the SMTP command verb from a client line.
func extractCommand(line string) string {
	upper := strings.ToUpper(line)
	for _, cmd := range smtpCommands {
		if strings.HasPrefix(upper, cmd) {
			return strings.TrimSpace(strings.SplitN(cmd, " ", 2)[0])
		}
	}
	// Fallback: first word.
	if idx := strings.IndexByte(line, ' '); idx > 0 {
		return strings.ToUpper(line[:idx])
	}
	return strings.ToUpper(line)
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

// Compile-time interface check.
var _ protocol.Parser = (*Parser)(nil)
