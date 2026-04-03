// Package postgres implements a parser for the PostgreSQL wire protocol (v3).
package postgres

import (
	"encoding/binary"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// Parser decodes PostgreSQL wire protocol messages.
type Parser struct {
	maxQueryLength int
}

// NewParser creates a PostgreSQL parser. maxQueryLength limits the captured SQL
// text length; zero means unlimited.
func NewParser(maxQueryLength int) *Parser {
	return &Parser{maxQueryLength: maxQueryLength}
}

func (p *Parser) Name() string    { return "postgres" }
func (p *Parser) Ports() []uint16 { return []uint16{5432} }

// Probe returns a confidence score that data belongs to the PostgreSQL protocol.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 8 {
		return 0
	}

	// Startup message from client: 4-byte length + version 3.0 (0x00030000).
	if isFromClient {
		version := binary.BigEndian.Uint32(data[4:8])
		if version == 0x00030000 {
			return 90
		}
	}

	// Tagged message: first byte is an ASCII uppercase letter.
	tag := data[0]
	if tag == 'Q' || tag == 'P' || tag == 'E' || tag == 'R' || tag == 'T' || tag == 'C' || tag == 'Z' {
		if len(data) >= 5 {
			msgLen := int(binary.BigEndian.Uint32(data[1:5]))
			if msgLen >= 4 && msgLen+1 <= len(data) {
				return 80
			}
		}
	}
	return 0
}

// Parse decodes PostgreSQL messages and returns protocol events.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	var events []*proto.ProtocolEvent

	// Handle startup message (no tag byte, starts with length + version).
	if isFromClient && len(data) >= 8 {
		version := binary.BigEndian.Uint32(data[4:8])
		if version == 0x00030000 {
			// Skip the startup message; nothing useful to extract here.
			msgLen := int(binary.BigEndian.Uint32(data[0:4]))
			if msgLen > 0 && msgLen <= len(data) {
				data = data[msgLen:]
			}
		}
	}

	for len(data) >= 5 {
		tag := data[0]
		msgLen := int(binary.BigEndian.Uint32(data[1:5])) // includes self (4 bytes) but not tag
		totalLen := 1 + msgLen
		if msgLen < 4 || totalLen > len(data) {
			break
		}
		payload := data[5:totalLen] // message body after tag+length

		ev := p.decodeMessage(tag, payload, meta, isFromClient)
		if ev != nil {
			events = append(events, ev)
		}
		data = data[totalLen:]
	}
	return events, nil
}

func (p *Parser) decodeMessage(tag byte, payload []byte, meta protocol.ConnMeta, isFromClient bool) *proto.ProtocolEvent {
	switch tag {
	case 'Q':
		return p.decodeSimpleQuery(payload, meta)
	case 'P':
		return p.decodeParse(payload, meta)
	case 'E':
		if !isFromClient {
			return p.decodeErrorResponse(payload, meta)
		}
		return nil
	default:
		return nil
	}
}

// decodeSimpleQuery handles the Simple Query message ('Q').
// Payload is a null-terminated SQL string.
func (p *Parser) decodeSimpleQuery(payload []byte, meta protocol.ConnMeta) *proto.ProtocolEvent {
	sql := cstring(payload)
	ev := proto.NewEvent("postgres", proto.DirectionRequest)
	fillMeta(ev, meta)
	ev.DBDetail = &proto.DBDetail{
		System:    "postgres",
		Operation: "SimpleQuery",
		Statement: p.truncate(sql),
	}
	return ev
}

// decodeParse handles the Parse message ('P') for extended query / prepared statements.
// Layout: name(cstring) + query(cstring) + param count(int16) + param OIDs.
func (p *Parser) decodeParse(payload []byte, meta protocol.ConnMeta) *proto.ProtocolEvent {
	// Skip statement name (first cstring).
	idx := nullTermIdx(payload)
	if idx < 0 {
		return nil
	}
	rest := payload[idx+1:]
	sql := cstring(rest)

	ev := proto.NewEvent("postgres", proto.DirectionRequest)
	fillMeta(ev, meta)
	ev.DBDetail = &proto.DBDetail{
		System:    "postgres",
		Operation: "Parse",
		Statement: p.truncate(sql),
	}
	return ev
}

// decodeErrorResponse handles the ErrorResponse message ('E') from the server.
// The body is a sequence of (byte-code, cstring) pairs terminated by '\0'.
func (p *Parser) decodeErrorResponse(payload []byte, meta protocol.ConnMeta) *proto.ProtocolEvent {
	var severity, code, msg string

	for len(payload) > 0 {
		fieldType := payload[0]
		payload = payload[1:]
		if fieldType == 0 {
			break
		}
		val := cstring(payload)
		advance := len(val) + 1
		if advance > len(payload) {
			break
		}
		payload = payload[advance:]

		switch fieldType {
		case 'S':
			severity = val
		case 'C':
			code = val
		case 'M':
			msg = val
		}
	}

	ev := proto.NewEvent("postgres", proto.DirectionResponse)
	fillMeta(ev, meta)
	ev.DBDetail = &proto.DBDetail{
		System:    "postgres",
		Operation: "ErrorResponse",
		ErrorMsg:  severity + " " + code + ": " + msg,
	}
	return ev
}

func (p *Parser) truncate(s string) string {
	if p.maxQueryLength > 0 && len(s) > p.maxQueryLength {
		return s[:p.maxQueryLength]
	}
	return s
}

// cstring extracts a null-terminated string from b.
func cstring(b []byte) string {
	idx := nullTermIdx(b)
	if idx < 0 {
		return string(b)
	}
	return string(b[:idx])
}

func nullTermIdx(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

func fillMeta(ev *proto.ProtocolEvent, meta protocol.ConnMeta) {
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)
}

// Compile-time interface check.
var _ protocol.Parser = (*Parser)(nil)
