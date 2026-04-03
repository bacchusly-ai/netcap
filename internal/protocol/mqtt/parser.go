// Package mqtt implements a parser for the MQTT protocol (v3.1.1 / v5).
package mqtt

import (
	"encoding/binary"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// MQTT packet types (high nibble of first byte).
const (
	pktCONNECT     byte = 1
	pktCONNACK     byte = 2
	pktPUBLISH     byte = 3
	pktPUBACK      byte = 4
	pktSUBSCRIBE   byte = 8
	pktUNSUBSCRIBE byte = 10
	pktPINGREQ     byte = 12
	pktPINGRESP    byte = 13
	pktDISCONNECT  byte = 14
)

var pktNames = map[byte]string{
	1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
	5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
	9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK",
	12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
}

// Parser decodes MQTT fixed headers and extracts key fields.
type Parser struct{}

func NewParser() *Parser               { return &Parser{} }
func (p *Parser) Name() string         { return "mqtt" }
func (p *Parser) Ports() []uint16      { return []uint16{1883, 8883} }

// Probe checks whether the data looks like an MQTT packet.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 2 {
		return 0
	}
	pktType := data[0] >> 4
	if pktType < 1 || pktType > 14 {
		return 0
	}
	// Validate remaining-length encoding.
	_, n := decodeRemainingLength(data[1:])
	if n <= 0 {
		return 0
	}
	// CONNECT packet starts with protocol name "MQTT" or "MQIsdp".
	if pktType == pktCONNECT && isFromClient {
		return 95
	}
	return 70
}

// Parse decodes the MQTT fixed header and extracts metadata.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	var events []*proto.ProtocolEvent

	for len(data) >= 2 {
		pktType := data[0] >> 4
		if pktType < 1 || pktType > 14 {
			break
		}
		remLen, lenBytes := decodeRemainingLength(data[1:])
		if lenBytes <= 0 {
			break
		}
		headerSize := 1 + lenBytes
		totalSize := headerSize + remLen
		if totalSize > len(data) {
			break
		}

		dir := proto.DirectionRequest
		if !isFromClient {
			dir = proto.DirectionResponse
		}

		ev := proto.NewEvent("mqtt", dir)
		fillMeta(ev, meta)
		ev.Metadata = map[string]string{
			"packet_type": pktNames[pktType],
		}

		payload := data[headerSize:totalSize]

		switch pktType {
		case pktCONNECT:
			if clientID := extractConnectClientID(payload); clientID != "" {
				ev.Metadata["client_id"] = clientID
			}
		case pktPUBLISH:
			if topic := extractPublishTopic(data[0], payload); topic != "" {
				ev.Metadata["topic"] = topic
			}
		}

		events = append(events, ev)
		data = data[totalSize:]
	}
	return events, nil
}

// decodeRemainingLength decodes the MQTT variable-length encoding.
// Returns (value, bytesConsumed). bytesConsumed <= 0 on error.
func decodeRemainingLength(data []byte) (int, int) {
	multiplier := 1
	value := 0
	for i := 0; i < 4 && i < len(data); i++ {
		value += int(data[i]&0x7F) * multiplier
		if data[i]&0x80 == 0 {
			return value, i + 1
		}
		multiplier *= 128
	}
	return 0, -1
}

// extractConnectClientID extracts the client ID from a CONNECT variable header + payload.
func extractConnectClientID(payload []byte) string {
	// Variable header: protocol name (length-prefixed string) + protocol level + flags + keep alive.
	if len(payload) < 10 {
		return ""
	}
	protoNameLen := int(binary.BigEndian.Uint16(payload[0:2]))
	offset := 2 + protoNameLen + 1 + 1 + 2 // name + level + flags + keepalive
	if offset+2 > len(payload) {
		return ""
	}
	clientIDLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if offset+clientIDLen > len(payload) {
		return ""
	}
	return string(payload[offset : offset+clientIDLen])
}

// extractPublishTopic extracts the topic from a PUBLISH payload.
func extractPublishTopic(firstByte byte, payload []byte) string {
	if len(payload) < 2 {
		return ""
	}
	topicLen := int(binary.BigEndian.Uint16(payload[0:2]))
	if 2+topicLen > len(payload) {
		return ""
	}
	return string(payload[2 : 2+topicLen])
}

func fillMeta(ev *proto.ProtocolEvent, meta protocol.ConnMeta) {
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)
}

var _ protocol.Parser = (*Parser)(nil)
