// Package redis implements a parser for the Redis Serialization Protocol (RESP).
package redis

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// RESP type prefix bytes.
const (
	respSimpleString byte = '+'
	respError        byte = '-'
	respInteger      byte = ':'
	respBulkString   byte = '$'
	respArray        byte = '*'
)

// Parser decodes RESP protocol messages.
type Parser struct {
	maxQueryLength int
}

// NewParser creates a Redis RESP parser. maxQueryLength limits the captured
// command text length; zero means unlimited.
func NewParser(maxQueryLength int) *Parser {
	return &Parser{maxQueryLength: maxQueryLength}
}

func (p *Parser) Name() string    { return "redis" }
func (p *Parser) Ports() []uint16 { return []uint16{6379, 6380} }

// Probe returns a confidence score that data belongs to the RESP protocol.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 3 {
		return 0
	}
	first := data[0]
	switch first {
	case respArray, respBulkString, respSimpleString, respError, respInteger:
		// Must have a \r\n somewhere near the start.
		if bytes.Contains(data[:min(len(data), 64)], []byte("\r\n")) {
			return 85
		}
		return 50
	}
	return 0
}

// Parse decodes RESP messages and returns protocol events.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	var events []*proto.ProtocolEvent

	for len(data) > 0 {
		ev, consumed := p.decodeOne(data, meta, isFromClient)
		if consumed <= 0 {
			break
		}
		if ev != nil {
			events = append(events, ev)
		}
		data = data[consumed:]
	}
	return events, nil
}

func (p *Parser) decodeOne(data []byte, meta protocol.ConnMeta, isFromClient bool) (*proto.ProtocolEvent, int) {
	if len(data) == 0 {
		return nil, 0
	}

	switch data[0] {
	case respArray:
		return p.decodeArray(data, meta, isFromClient)
	case respError:
		return p.decodeError(data, meta)
	default:
		// Skip non-interesting RESP values (simple strings, integers, bulk strings).
		_, n := readRESPValue(data)
		return nil, n
	}
}

// decodeArray parses a RESP array which represents a Redis command from the client.
func (p *Parser) decodeArray(data []byte, meta protocol.ConnMeta, isFromClient bool) (*proto.ProtocolEvent, int) {
	line, pos := readLine(data)
	if pos < 0 {
		return nil, 0
	}

	count, err := strconv.Atoi(string(line[1:])) // skip '*'
	if err != nil || count < 0 {
		return nil, 0
	}

	var args []string
	cursor := pos
	for i := 0; i < count; i++ {
		val, n := readRESPValue(data[cursor:])
		if n <= 0 {
			return nil, 0
		}
		args = append(args, val)
		cursor += n
	}

	if len(args) == 0 {
		return nil, cursor
	}

	dir := proto.DirectionRequest
	if !isFromClient {
		dir = proto.DirectionResponse
	}

	cmdName := strings.ToUpper(args[0])
	fullCmd := strings.Join(args, " ")
	if p.maxQueryLength > 0 && len(fullCmd) > p.maxQueryLength {
		fullCmd = fullCmd[:p.maxQueryLength]
	}

	ev := proto.NewEvent("redis", dir)
	fillMeta(ev, meta)
	ev.DBDetail = &proto.DBDetail{
		System:    "redis",
		Operation: cmdName,
		Statement: fullCmd,
	}
	return ev, cursor
}

// decodeError parses a RESP error line: -ERR message\r\n
func (p *Parser) decodeError(data []byte, meta protocol.ConnMeta) (*proto.ProtocolEvent, int) {
	line, pos := readLine(data)
	if pos < 0 {
		return nil, 0
	}
	msg := string(line[1:]) // skip '-'

	ev := proto.NewEvent("redis", proto.DirectionResponse)
	fillMeta(ev, meta)
	ev.DBDetail = &proto.DBDetail{
		System:    "redis",
		Operation: "ERR",
		ErrorMsg:  msg,
	}
	return ev, pos
}

// readLine reads up to the next \r\n and returns the line content and the
// position immediately after \r\n. Returns -1 if no \r\n found.
func readLine(data []byte) ([]byte, int) {
	idx := bytes.Index(data, []byte("\r\n"))
	if idx < 0 {
		return nil, -1
	}
	return data[:idx], idx + 2
}

// readRESPValue reads one RESP value and returns its string representation and
// total bytes consumed. Returns ("", 0) on parse failure.
func readRESPValue(data []byte) (string, int) {
	if len(data) == 0 {
		return "", 0
	}

	switch data[0] {
	case respSimpleString, respError, respInteger:
		line, pos := readLine(data)
		if pos < 0 {
			return "", 0
		}
		return string(line[1:]), pos

	case respBulkString:
		line, pos := readLine(data)
		if pos < 0 {
			return "", 0
		}
		length, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return "", 0
		}
		if length < 0 {
			// Null bulk string.
			return "(nil)", pos
		}
		end := pos + length + 2 // +2 for trailing \r\n
		if end > len(data) {
			return "", 0
		}
		return string(data[pos : pos+length]), end

	case respArray:
		// Nested arrays: skip through all elements.
		line, pos := readLine(data)
		if pos < 0 {
			return "", 0
		}
		count, err := strconv.Atoi(string(line[1:]))
		if err != nil || count < 0 {
			return "", 0
		}
		cursor := pos
		for i := 0; i < count; i++ {
			_, n := readRESPValue(data[cursor:])
			if n <= 0 {
				return "", 0
			}
			cursor += n
		}
		return "(array)", cursor

	default:
		// Inline command: read until \r\n.
		line, pos := readLine(data)
		if pos < 0 {
			return "", 0
		}
		return string(line), pos
	}
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
