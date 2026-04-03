// Package mongodb implements a parser for the MongoDB wire protocol.
package mongodb

import (
	"encoding/binary"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// MongoDB wire protocol opcodes.
const (
	opReply       uint32 = 1    // OP_REPLY (deprecated but still seen)
	opMsg         uint32 = 2013 // OP_MSG (MongoDB 3.6+)
	opQuery       uint32 = 2004 // OP_QUERY (deprecated)
	opCompressed  uint32 = 2012 // OP_COMPRESSED
)

// MongoDB header size: messageLength(4) + requestID(4) + responseTo(4) + opCode(4).
const headerSize = 16

// Parser decodes MongoDB wire protocol messages.
type Parser struct {
	maxQueryLength int
}

// NewParser creates a MongoDB parser. maxQueryLength limits the captured command
// text length; zero means unlimited.
func NewParser(maxQueryLength int) *Parser {
	return &Parser{maxQueryLength: maxQueryLength}
}

func (p *Parser) Name() string    { return "mongodb" }
func (p *Parser) Ports() []uint16 { return []uint16{27017, 27018, 27019} }

// Probe returns a confidence score that data belongs to the MongoDB wire protocol.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < headerSize {
		return 0
	}

	msgLen := binary.LittleEndian.Uint32(data[0:4])
	opCode := binary.LittleEndian.Uint32(data[12:16])

	// Sanity: declared length should roughly match available data and be reasonable.
	if msgLen < headerSize || msgLen > 48*1024*1024 {
		return 0
	}

	switch opCode {
	case opMsg:
		return 90
	case opQuery, opReply, opCompressed:
		return 75
	}
	return 0
}

// Parse decodes MongoDB messages and returns protocol events.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	var events []*proto.ProtocolEvent

	for len(data) >= headerSize {
		msgLen := int(binary.LittleEndian.Uint32(data[0:4]))
		if msgLen < headerSize || msgLen > len(data) {
			break
		}
		opCode := binary.LittleEndian.Uint32(data[12:16])
		body := data[headerSize:msgLen]

		ev := p.decodeMessage(opCode, body, meta, isFromClient)
		if ev != nil {
			events = append(events, ev)
		}
		data = data[msgLen:]
	}
	return events, nil
}

func (p *Parser) decodeMessage(opCode uint32, body []byte, meta protocol.ConnMeta, isFromClient bool) *proto.ProtocolEvent {
	switch opCode {
	case opMsg:
		return p.decodeOpMsg(body, meta, isFromClient)
	case opQuery:
		return p.decodeOpQuery(body, meta)
	default:
		return nil
	}
}

// decodeOpMsg handles OP_MSG messages (MongoDB 3.6+).
// Layout: flagBits(4) + sections...
// Section Kind 0: BSON document.
func (p *Parser) decodeOpMsg(body []byte, meta protocol.ConnMeta, isFromClient bool) *proto.ProtocolEvent {
	if len(body) < 5 {
		return nil
	}
	// Skip flagBits (4 bytes).
	sectionData := body[4:]

	// We only handle Kind 0 (single BSON document).
	if len(sectionData) < 1 {
		return nil
	}
	kind := sectionData[0]
	if kind != 0 {
		return nil
	}
	bsonDoc := sectionData[1:]

	cmdName, collection := extractFirstKey(bsonDoc)
	if cmdName == "" {
		return nil
	}

	dir := proto.DirectionRequest
	if !isFromClient {
		dir = proto.DirectionResponse
	}

	ev := proto.NewEvent("mongodb", dir)
	fillMeta(ev, meta)
	ev.DBDetail = &proto.DBDetail{
		System:    "mongodb",
		Operation: cmdName,
		Table:     collection,
	}
	return ev
}

// decodeOpQuery handles legacy OP_QUERY messages.
// Layout: flags(4) + fullCollectionName(cstring) + numberToSkip(4) + numberToReturn(4) + query(BSON).
func (p *Parser) decodeOpQuery(body []byte, meta protocol.ConnMeta) *proto.ProtocolEvent {
	if len(body) < 4 {
		return nil
	}
	// Skip flags.
	rest := body[4:]
	collName := readCString(rest)
	if collName == "" {
		return nil
	}

	ev := proto.NewEvent("mongodb", proto.DirectionRequest)
	fillMeta(ev, meta)
	ev.DBDetail = &proto.DBDetail{
		System:    "mongodb",
		Operation: "query",
		Table:     collName,
	}
	return ev
}

// extractFirstKey does a simplified BSON parse to extract the first key name
// from a BSON document, which in MongoDB commands is the command name.
// It also returns the string value if the first element is a string (often the
// collection name).
//
// BSON document layout: totalSize(4LE) + elements... + '\x00'
// Element: type(1) + cstring-key + value
func extractFirstKey(data []byte) (key string, strVal string) {
	if len(data) < 5 {
		return "", ""
	}
	docLen := int(binary.LittleEndian.Uint32(data[0:4]))
	if docLen < 5 || docLen > len(data) {
		return "", ""
	}

	// First element starts at byte 4.
	elem := data[4:]
	if len(elem) < 2 {
		return "", ""
	}

	elemType := elem[0]
	elem = elem[1:]

	key = readCString(elem)
	if key == "" {
		return "", ""
	}

	// Advance past the key cstring.
	valStart := len(key) + 1 // +1 for null terminator
	if valStart >= len(elem) {
		return key, ""
	}
	valData := elem[valStart:]

	// If the value is a UTF-8 string (type 0x02), extract it.
	if elemType == 0x02 && len(valData) >= 4 {
		strLen := int(binary.LittleEndian.Uint32(valData[0:4]))
		if strLen > 0 && strLen-1 <= len(valData)-4 {
			strVal = string(valData[4 : 4+strLen-1]) // -1 to exclude null terminator
		}
	}
	return key, strVal
}

// readCString reads a null-terminated string from the beginning of data.
func readCString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return ""
}

func fillMeta(ev *proto.ProtocolEvent, meta protocol.ConnMeta) {
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)
}

// Compile-time interface check.
var _ protocol.Parser = (*Parser)(nil)
