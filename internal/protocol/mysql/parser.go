// Package mysql implements a parser for the MySQL wire protocol.
package mysql

import (
	"encoding/binary"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// MySQL command byte constants.
const (
	comQuery       byte = 0x03
	comStmtPrepare byte = 0x16

	okMarker  byte = 0x00
	errMarker byte = 0xff
	eofMarker byte = 0xfe
)

// Parser decodes MySQL wire protocol packets.
type Parser struct {
	maxQueryLength int
}

// NewParser creates a MySQL parser. maxQueryLength limits the captured SQL text
// length; zero means unlimited.
func NewParser(maxQueryLength int) *Parser {
	return &Parser{maxQueryLength: maxQueryLength}
}

func (p *Parser) Name() string        { return "mysql" }
func (p *Parser) Ports() []uint16     { return []uint16{3306, 33060} }

// Probe checks whether data looks like a MySQL packet.
// For server->client the first handshake has seq=0 and protocol_version=0x0a.
// For client->server we look for valid packet header with a known command byte.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 5 {
		return 0
	}

	// Server handshake greeting: 3-byte length + seq 0 + protocol_version 10.
	if !isFromClient {
		if data[3] == 0x00 && data[4] == 0x0a {
			return 90
		}
	}

	// Client command packet: validate payload length and known command byte.
	payloadLen := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
	if payloadLen > 0 && payloadLen+4 <= len(data) {
		cmd := data[4]
		if cmd == comQuery || cmd == comStmtPrepare {
			return 70
		}
	}
	return 0
}

// Parse decodes one or more MySQL packets from data and returns protocol events.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	var events []*proto.ProtocolEvent

	for len(data) >= 4 {
		// MySQL packet: 3-byte payload length (LE) + 1-byte sequence id.
		payloadLen := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
		packetLen := 4 + payloadLen
		if packetLen > len(data) || payloadLen == 0 {
			break
		}
		payload := data[4:packetLen]

		ev := p.decodePacket(payload, meta, isFromClient)
		if ev != nil {
			events = append(events, ev)
		}
		data = data[packetLen:]
	}
	return events, nil
}

func (p *Parser) decodePacket(payload []byte, meta protocol.ConnMeta, isFromClient bool) *proto.ProtocolEvent {
	if len(payload) == 0 {
		return nil
	}

	if isFromClient {
		return p.decodeCommand(payload, meta)
	}
	return p.decodeResponse(payload, meta)
}

func (p *Parser) decodeCommand(payload []byte, meta protocol.ConnMeta) *proto.ProtocolEvent {
	cmd := payload[0]
	var opName, stmt string

	switch cmd {
	case comQuery:
		opName = "COM_QUERY"
		stmt = p.extractString(payload[1:])
	case comStmtPrepare:
		opName = "COM_STMT_PREPARE"
		stmt = p.extractString(payload[1:])
	default:
		return nil
	}

	ev := proto.NewEvent("mysql", proto.DirectionRequest)
	fillMeta(ev, meta)
	ev.DBDetail = &proto.DBDetail{
		System:    "mysql",
		Operation: opName,
		Statement: stmt,
	}
	return ev
}

func (p *Parser) decodeResponse(payload []byte, meta protocol.ConnMeta) *proto.ProtocolEvent {
	marker := payload[0]

	switch marker {
	case okMarker:
		ev := proto.NewEvent("mysql", proto.DirectionResponse)
		fillMeta(ev, meta)
		ev.DBDetail = &proto.DBDetail{
			System:    "mysql",
			Operation: "OK",
		}
		return ev

	case errMarker:
		if len(payload) < 3 {
			return nil
		}
		errCode := binary.LittleEndian.Uint16(payload[1:3])
		// After the error code there may be a '#' + 5-char SQLSTATE, then the message.
		msg := ""
		rest := payload[3:]
		if len(rest) > 0 && rest[0] == '#' && len(rest) > 6 {
			msg = string(rest[6:])
		} else {
			msg = string(rest)
		}

		ev := proto.NewEvent("mysql", proto.DirectionResponse)
		fillMeta(ev, meta)
		ev.DBDetail = &proto.DBDetail{
			System:    "mysql",
			Operation: "ERR",
			ErrorCode: int32(errCode),
			ErrorMsg:  msg,
		}
		return ev

	default:
		return nil
	}
}

func (p *Parser) extractString(b []byte) string {
	s := string(b)
	if p.maxQueryLength > 0 && len(s) > p.maxQueryLength {
		return s[:p.maxQueryLength]
	}
	return s
}

func fillMeta(ev *proto.ProtocolEvent, meta protocol.ConnMeta) {
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)
}

// Compile-time interface check.
var _ protocol.Parser = (*Parser)(nil)

