// Package tls implements a TLS ClientHello parser with JA3 fingerprinting.
package tls

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// Parser detects and decodes TLS ClientHello messages.
type Parser struct{}

var _ protocol.Parser = (*Parser)(nil)

func (p *Parser) Name() string    { return "tls" }
func (p *Parser) Ports() []uint16 { return []uint16{443, 8443, 993, 995, 465, 636} }

// Probe checks for a TLS record header: content type 0x16 (Handshake) and
// major version 0x03.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 6 && len(data) >= 3 {
		if data[0] == 0x16 && data[1] == 0x03 {
			return 60
		}
		return 0
	}
	if len(data) < 6 {
		return 0
	}
	if data[0] == 0x16 && data[1] == 0x03 {
		return 85
	}
	return 0
}

// Parse decodes a TLS record containing a ClientHello and populates TLSDetail
// including the JA3 hash.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("tls: record too short")
	}

	// TLS record header: type(1) + version(2) + length(2).
	contentType := data[0]
	if contentType != 0x16 {
		return nil, fmt.Errorf("tls: not a handshake record (type=0x%02x)", contentType)
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+recordLen > len(data) {
		// Truncated record; work with what we have.
		recordLen = len(data) - 5
	}
	payload := data[5 : 5+recordLen]

	// Handshake header: type(1) + length(3).
	if len(payload) < 4 {
		return nil, fmt.Errorf("tls: handshake header truncated")
	}
	hsType := payload[0]
	if hsType != 0x01 {
		// Not a ClientHello; still valid TLS but nothing to extract.
		ev := proto.NewEvent("tls", proto.DirectionRequest)
		ev.SrcIP = meta.SrcIP
		ev.DstIP = meta.DstIP
		ev.SrcPort = uint32(meta.SrcPort)
		ev.DstPort = uint32(meta.DstPort)
		ev.TLSDetail = &proto.TLSDetail{
			HandshakeType: int32(hsType),
			Version:       versionString(data[1], data[2]),
		}
		return []*proto.ProtocolEvent{ev}, nil
	}

	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	hs := payload[4:]
	if hsLen < len(hs) {
		hs = hs[:hsLen]
	}

	return p.parseClientHello(hs, data[1], data[2], meta)
}

// parseClientHello dissects the ClientHello body.
func (p *Parser) parseClientHello(hs []byte, recMajor, recMinor byte, meta protocol.ConnMeta) ([]*proto.ProtocolEvent, error) {
	if len(hs) < 38 {
		return nil, fmt.Errorf("tls: ClientHello too short")
	}

	// Client version (2 bytes).
	chVersion := binary.BigEndian.Uint16(hs[0:2])
	// Random (32 bytes) -- skip.
	off := 34

	// Session ID.
	if off >= len(hs) {
		return nil, fmt.Errorf("tls: session id length truncated")
	}
	sidLen := int(hs[off])
	off++
	off += sidLen
	if off > len(hs) {
		return nil, fmt.Errorf("tls: session id truncated")
	}

	// Cipher suites.
	if off+2 > len(hs) {
		return nil, fmt.Errorf("tls: cipher suites length truncated")
	}
	csLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2
	if off+csLen > len(hs) {
		return nil, fmt.Errorf("tls: cipher suites truncated")
	}
	var cipherSuites []uint16
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(hs[off+i : off+i+2])
		cipherSuites = append(cipherSuites, cs)
	}
	off += csLen

	// Compression methods.
	if off >= len(hs) {
		return nil, fmt.Errorf("tls: compression length truncated")
	}
	compLen := int(hs[off])
	off++
	off += compLen
	if off > len(hs) {
		return nil, fmt.Errorf("tls: compression truncated")
	}

	// Extensions.
	var (
		sni          string
		alpn         []string
		extTypes     []uint16
		ellipticCurves []uint16
		ecPointFmts  []uint8
	)

	if off+2 <= len(hs) {
		extTotalLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
		off += 2
		extEnd := off + extTotalLen
		if extEnd > len(hs) {
			extEnd = len(hs)
		}

		for off+4 <= extEnd {
			extType := binary.BigEndian.Uint16(hs[off : off+2])
			extLen := int(binary.BigEndian.Uint16(hs[off+2 : off+4]))
			off += 4
			extData := hs[off:]
			if extLen < len(extData) {
				extData = extData[:extLen]
			}
			extTypes = append(extTypes, extType)

			switch extType {
			case 0x0000: // SNI
				sni = parseSNI(extData)
			case 0x0010: // ALPN
				alpn = parseALPN(extData)
			case 0x000A: // Supported Groups (elliptic curves)
				ellipticCurves = parseU16List(extData)
			case 0x000B: // EC Point Formats
				ecPointFmts = parseU8List(extData)
			}

			off += extLen
		}
	}

	// Build JA3 string: TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
	ja3Raw := buildJA3(chVersion, cipherSuites, extTypes, ellipticCurves, ecPointFmts)
	ja3Hash := fmt.Sprintf("%x", md5.Sum([]byte(ja3Raw)))

	ev := proto.NewEvent("tls", proto.DirectionRequest)
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)

	ev.TLSDetail = &proto.TLSDetail{
		Version:       versionString(recMajor, recMinor),
		HandshakeType: 1, // ClientHello
		ServerName:    sni,
		ALPNProtocols: alpn,
		CipherSuite:   ja3Hash, // Store JA3 hash in CipherSuite for now.
	}
	if ev.Metadata == nil {
		ev.Metadata = make(map[string]string)
	}
	ev.Metadata["ja3"] = ja3Hash
	ev.Metadata["ja3_raw"] = ja3Raw

	return []*proto.ProtocolEvent{ev}, nil
}

// ---------------------------------------------------------------------------
// Extension helpers
// ---------------------------------------------------------------------------

// parseSNI extracts the first host_name from a Server Name Indication extension.
func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// listLen := binary.BigEndian.Uint16(data[0:2])
	nameType := data[2]
	if nameType != 0 { // host_name
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

// parseALPN extracts protocol names from an ALPN extension.
func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	off := 2
	end := 2 + listLen
	if end > len(data) {
		end = len(data)
	}
	var protocols []string
	for off < end {
		pLen := int(data[off])
		off++
		if off+pLen > end {
			break
		}
		protocols = append(protocols, string(data[off:off+pLen]))
		off += pLen
	}
	return protocols
}

// parseU16List reads a 2-byte-length-prefixed list of uint16 values.
func parseU16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	off := 2
	end := 2 + listLen
	if end > len(data) {
		end = len(data)
	}
	var out []uint16
	for off+2 <= end {
		out = append(out, binary.BigEndian.Uint16(data[off:off+2]))
		off += 2
	}
	return out
}

// parseU8List reads a 1-byte-length-prefixed list of uint8 values.
func parseU8List(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	off := 1
	end := 1 + listLen
	if end > len(data) {
		end = len(data)
	}
	var out []uint8
	for off < end {
		out = append(out, data[off])
		off++
	}
	return out
}

// ---------------------------------------------------------------------------
// JA3 fingerprint
// ---------------------------------------------------------------------------

// buildJA3 constructs the raw JA3 string:
//   TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
//
// GREASE values (0x?a?a) are excluded per the JA3 spec.
func buildJA3(version uint16, ciphers, extensions []uint16, curves []uint16, pointFmts []uint8) string {
	var b strings.Builder

	// TLS version.
	fmt.Fprintf(&b, "%d,", version)

	// Cipher suites (dash-separated).
	b.WriteString(joinU16(filterGREASE(ciphers)))
	b.WriteByte(',')

	// Extensions (dash-separated).
	b.WriteString(joinU16(filterGREASE(extensions)))
	b.WriteByte(',')

	// Elliptic curves.
	b.WriteString(joinU16(filterGREASE(curves)))
	b.WriteByte(',')

	// EC point formats.
	b.WriteString(joinU8(pointFmts))

	return b.String()
}

// isGREASE returns true if the value is a TLS GREASE value (RFC 8701).
func isGREASE(v uint16) bool {
	return (v&0x0F0F) == 0x0A0A && (v>>8) == (v&0xFF)
}

func filterGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinU16(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

func joinU8(vals []uint8) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

// versionString returns a human-readable TLS version.
func versionString(major, minor byte) string {
	switch {
	case major == 3 && minor == 3:
		return "TLS 1.2"
	case major == 3 && minor == 1:
		return "TLS 1.0"
	case major == 3 && minor == 2:
		return "TLS 1.1"
	case major == 3 && minor == 4:
		return "TLS 1.3"
	case major == 3 && minor == 0:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("TLS 0x%02x%02x", major, minor)
	}
}
