// Package ssh implements a parser for the SSH protocol version exchange.
package ssh

import (
	"bytes"
	"strings"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// Parser decodes SSH version strings.
type Parser struct{}

func NewParser() *Parser               { return &Parser{} }
func (p *Parser) Name() string         { return "ssh" }
func (p *Parser) Ports() []uint16      { return []uint16{22} }

// Probe returns a confidence score for SSH traffic.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) >= 4 && bytes.HasPrefix(data, []byte("SSH-")) {
		return 95
	}
	return 0
}

// Parse extracts the SSH version string.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	if len(data) < 4 {
		return nil, nil
	}

	dir := proto.DirectionRequest
	if !isFromClient {
		dir = proto.DirectionResponse
	}

	// The version string ends at \r\n or \n.
	line := data
	if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
		line = data[:idx]
	}
	line = bytes.TrimRight(line, "\r")
	versionStr := string(line)

	ev := proto.NewEvent("ssh", dir)
	fillMeta(ev, meta)
	ev.Metadata = map[string]string{"version_string": versionStr}

	// Try to extract software version: SSH-2.0-OpenSSH_8.9 -> "OpenSSH_8.9".
	parts := strings.SplitN(versionStr, "-", 3)
	if len(parts) == 3 {
		ev.Metadata["protocol_version"] = parts[0] + "-" + parts[1]
		ev.Metadata["software"] = parts[2]
	}

	return []*proto.ProtocolEvent{ev}, nil
}

func fillMeta(ev *proto.ProtocolEvent, meta protocol.ConnMeta) {
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)
}

var _ protocol.Parser = (*Parser)(nil)
