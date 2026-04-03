// Package unknown implements a fallback parser for unrecognized protocols.
package unknown

import (
	"encoding/hex"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

const maxExcerptLen = 128

// Parser is the lowest-priority fallback for unrecognized traffic.
type Parser struct{}

func NewParser() *Parser               { return &Parser{} }
func (p *Parser) Name() string         { return "unknown" }
func (p *Parser) Ports() []uint16      { return nil }

// Probe always returns 1 (lowest priority) so this parser is only used
// when no other parser matches.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) == 0 {
		return 0
	}
	return 1
}

// Parse captures a hex excerpt of the raw payload.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	if len(data) == 0 {
		return nil, nil
	}

	dir := proto.DirectionRequest
	if !isFromClient {
		dir = proto.DirectionResponse
	}

	excerpt := data
	if len(excerpt) > maxExcerptLen {
		excerpt = excerpt[:maxExcerptLen]
	}

	ev := proto.NewEvent("unknown", dir)
	fillMeta(ev, meta)
	ev.RawExcerpt = excerpt
	ev.Metadata = map[string]string{
		"raw_hex":    hex.EncodeToString(excerpt),
		"total_size": intToStr(len(data)),
	}
	return []*proto.ProtocolEvent{ev}, nil
}

func intToStr(n int) string {
	// Simple int-to-string without importing strconv to keep deps minimal.
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// Reverse.
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func fillMeta(ev *proto.ProtocolEvent, meta protocol.ConnMeta) {
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)
}

var _ protocol.Parser = (*Parser)(nil)
