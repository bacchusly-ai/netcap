// Package dns implements a hand-written DNS protocol parser (no external deps).
package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// Parser detects and decodes DNS messages.
type Parser struct{}

var _ protocol.Parser = (*Parser)(nil)

func (p *Parser) Name() string        { return "dns" }
func (p *Parser) Ports() []uint16     { return []uint16{53, 5353} }

// Probe checks whether data looks like a DNS message.
// Minimum 12 bytes (header), QDCount <= 10.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 12 {
		return 0
	}
	qdCount := binary.BigEndian.Uint16(data[4:6])
	if qdCount == 0 || qdCount > 10 {
		return 0
	}
	// Opcode should be <= 5 (standard, inverse, status, notify, update, DSO).
	opcode := (data[2] >> 3) & 0x0F
	if opcode > 5 {
		return 0
	}
	return 80
}

// Parse decodes a DNS message into ProtocolEvents.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("dns: packet too short (%d bytes)", len(data))
	}

	txID := binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])
	// nsCount and arCount are at [8:10] and [10:12]; we skip them.

	opcode := int32((flags >> 11) & 0x0F)
	rcode := int32(flags & 0x0F)
	isResponse := (flags & 0x8000) != 0

	dir := proto.DirectionRequest
	if isResponse {
		dir = proto.DirectionResponse
	}

	ev := proto.NewEvent("dns", dir)
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)

	detail := &proto.DNSDetail{
		TransactionID: txID,
		OpCode:        opcode,
		ResponseCode:  rcode,
	}

	offset := 12

	// Parse question section.
	for i := 0; i < int(qdCount); i++ {
		name, newOff, err := decodeName(data, offset)
		if err != nil {
			return nil, fmt.Errorf("dns: question name: %w", err)
		}
		offset = newOff
		if offset+4 > len(data) {
			return nil, fmt.Errorf("dns: question truncated")
		}
		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		qclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		detail.Questions = append(detail.Questions, proto.DNSQuestion{
			Name:  name,
			Type:  rrTypeName(qtype),
			Class: rrClassName(qclass),
		})
	}

	// Parse answer section.
	for i := 0; i < int(anCount); i++ {
		name, newOff, err := decodeName(data, offset)
		if err != nil {
			return nil, fmt.Errorf("dns: answer name: %w", err)
		}
		offset = newOff
		if offset+10 > len(data) {
			return nil, fmt.Errorf("dns: answer truncated")
		}
		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		rclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdLength := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(data) {
			return nil, fmt.Errorf("dns: rdata truncated")
		}
		rdata := data[offset : offset+int(rdLength)]
		offset += int(rdLength)

		detail.Answers = append(detail.Answers, proto.DNSAnswer{
			Name:  name,
			Type:  rrTypeName(rtype),
			Class: rrClassName(rclass),
			TTL:   ttl,
			Data:  formatRData(rtype, rdata, data),
		})
	}

	ev.DNSDetail = detail
	return []*proto.ProtocolEvent{ev}, nil
}

// ---------------------------------------------------------------------------
// DNS name decoding with label compression (pointer = 0xC0 prefix)
// ---------------------------------------------------------------------------

// decodeName reads a DNS domain name starting at offset, handling compression
// pointers. Returns the decoded name and the new offset past the name field.
func decodeName(data []byte, offset int) (string, int, error) {
	var parts []string
	visited := make(map[int]bool) // loop detection
	newOffset := -1               // tracks the offset to return (set on first pointer)
	cur := offset

	for {
		if cur >= len(data) {
			return "", 0, fmt.Errorf("offset %d out of bounds", cur)
		}
		length := int(data[cur])

		if length == 0 {
			// End of name.
			if newOffset < 0 {
				newOffset = cur + 1
			}
			break
		}

		// Compression pointer: top two bits set (0xC0).
		if length&0xC0 == 0xC0 {
			if cur+1 >= len(data) {
				return "", 0, fmt.Errorf("pointer truncated at %d", cur)
			}
			ptr := int(binary.BigEndian.Uint16(data[cur:cur+2]) & 0x3FFF)
			if visited[ptr] {
				return "", 0, fmt.Errorf("compression loop at %d", ptr)
			}
			visited[ptr] = true
			if newOffset < 0 {
				newOffset = cur + 2
			}
			cur = ptr
			continue
		}

		// Normal label.
		cur++
		end := cur + length
		if end > len(data) {
			return "", 0, fmt.Errorf("label extends past packet at %d", cur)
		}
		parts = append(parts, string(data[cur:end]))
		cur = end
	}

	return strings.Join(parts, "."), newOffset, nil
}

// ---------------------------------------------------------------------------
// RR type / class helpers
// ---------------------------------------------------------------------------

func rrTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func rrClassName(c uint16) string {
	switch c {
	case 1:
		return "IN"
	case 3:
		return "CH"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", c)
	}
}

// formatRData converts rdata bytes to a human-readable string based on RR type.
func formatRData(rtype uint16, rdata []byte, pkt []byte) string {
	switch rtype {
	case 1: // A
		if len(rdata) == 4 {
			return net.IP(rdata).String()
		}
	case 28: // AAAA
		if len(rdata) == 16 {
			return net.IP(rdata).String()
		}
	case 5, 2, 12: // CNAME, NS, PTR
		name, _, err := decodeName(pkt, -1)
		// Try decoding from the rdata start within the full packet.
		_ = name
		_ = err
		// Fall back: decode the rdata as a name within the full packet context.
		// We need the absolute offset, so we compute it.
		if len(pkt) > 0 && len(rdata) > 0 {
			// Find rdata offset in the packet.
			rdataStart := findOffset(pkt, rdata)
			if rdataStart >= 0 {
				if n, _, err := decodeName(pkt, rdataStart); err == nil {
					return n
				}
			}
		}
	case 15: // MX
		if len(rdata) >= 3 {
			pref := binary.BigEndian.Uint16(rdata[0:2])
			rdataStart := findOffset(pkt, rdata)
			if rdataStart >= 0 {
				if n, _, err := decodeName(pkt, rdataStart+2); err == nil {
					return fmt.Sprintf("%d %s", pref, n)
				}
			}
		}
	case 16: // TXT
		if len(rdata) > 0 {
			var texts []string
			off := 0
			for off < len(rdata) {
				tlen := int(rdata[off])
				off++
				if off+tlen > len(rdata) {
					break
				}
				texts = append(texts, string(rdata[off:off+tlen]))
				off += tlen
			}
			return strings.Join(texts, " ")
		}
	}
	return fmt.Sprintf("%x", rdata)
}

// findOffset returns the byte offset of sub within pkt, or -1.
func findOffset(pkt, sub []byte) int {
	if len(sub) == 0 || len(pkt) == 0 {
		return -1
	}
	// Since rdata is a slice of pkt, we can use pointer arithmetic via cap
	// comparison, but for safety we just search.
	for i := 0; i+len(sub) <= len(pkt); i++ {
		if &pkt[i] == &sub[0] {
			return i
		}
	}
	return -1
}
