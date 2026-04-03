// Package websocket implements a parser for WebSocket upgrade requests and frames.
package websocket

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// WebSocket frame opcodes.
const (
	opContinuation byte = 0x0
	opText         byte = 0x1
	opBinary       byte = 0x2
	opClose        byte = 0x8
	opPing         byte = 0x9
	opPong         byte = 0xA
)

var opcodeNames = map[byte]string{
	0x0: "continuation", 0x1: "text", 0x2: "binary",
	0x8: "close", 0x9: "ping", 0xA: "pong",
}

// Parser decodes WebSocket upgrade handshakes and frame headers.
type Parser struct{}

func NewParser() *Parser               { return &Parser{} }
func (p *Parser) Name() string         { return "websocket" }
func (p *Parser) Ports() []uint16      { return []uint16{80, 443, 8080} }

// Probe returns a confidence score for WebSocket traffic.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	if len(data) < 4 {
		return 0
	}

	// Check for HTTP upgrade to WebSocket.
	if isFromClient && bytes.HasPrefix(data, []byte("GET ")) {
		header := string(data[:min(len(data), 512)])
		if containsIgnoreCase(header, "upgrade: websocket") {
			return 95
		}
	}

	// Check for server 101 Switching Protocols.
	if !isFromClient && bytes.HasPrefix(data, []byte("HTTP/1.1 101")) {
		header := string(data[:min(len(data), 512)])
		if containsIgnoreCase(header, "upgrade: websocket") {
			return 95
		}
	}

	// Check for WebSocket frame: first byte has FIN bit and valid opcode.
	if len(data) >= 2 {
		opcode := data[0] & 0x0F
		if opcode <= 0x2 || (opcode >= 0x8 && opcode <= 0xA) {
			fin := data[0] & 0x80
			if fin != 0 {
				return 40 // Low confidence; could be anything.
			}
		}
	}
	return 0
}

// Parse decodes either a WebSocket HTTP upgrade or a WebSocket frame header.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	// Try HTTP upgrade first.
	if ev := p.parseUpgrade(data, meta, isFromClient); ev != nil {
		return []*proto.ProtocolEvent{ev}, nil
	}

	// Try WebSocket frame.
	if ev := p.parseFrame(data, meta, isFromClient); ev != nil {
		return []*proto.ProtocolEvent{ev}, nil
	}
	return nil, nil
}

// parseUpgrade handles WebSocket HTTP upgrade requests/responses.
func (p *Parser) parseUpgrade(data []byte, meta protocol.ConnMeta, isFromClient bool) *proto.ProtocolEvent {
	s := string(data[:min(len(data), 1024)])
	if !containsIgnoreCase(s, "upgrade: websocket") {
		return nil
	}

	dir := proto.DirectionRequest
	if !isFromClient {
		dir = proto.DirectionResponse
	}

	ev := proto.NewEvent("websocket", dir)
	fillMeta(ev, meta)
	ev.Metadata = map[string]string{"type": "upgrade"}

	// Extract key headers.
	lines := strings.Split(s, "\r\n")
	if len(lines) > 0 {
		ev.Metadata["request_line"] = lines[0]
	}
	for _, line := range lines[1:] {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "sec-websocket-key:") {
			ev.Metadata["ws_key"] = strings.TrimSpace(line[len("Sec-WebSocket-Key:"):])
		} else if strings.HasPrefix(lower, "sec-websocket-protocol:") {
			ev.Metadata["ws_protocol"] = strings.TrimSpace(line[len("Sec-WebSocket-Protocol:"):])
		}
	}
	return ev
}

// parseFrame decodes a WebSocket frame header.
func (p *Parser) parseFrame(data []byte, meta protocol.ConnMeta, isFromClient bool) *proto.ProtocolEvent {
	if len(data) < 2 {
		return nil
	}
	opcode := data[0] & 0x0F
	if _, ok := opcodeNames[opcode]; !ok {
		return nil
	}

	fin := (data[0] & 0x80) != 0
	masked := (data[1] & 0x80) != 0
	payloadLen := int(data[1] & 0x7F)

	dir := proto.DirectionRequest
	if !isFromClient {
		dir = proto.DirectionResponse
	}
	ev := proto.NewEvent("websocket", dir)
	fillMeta(ev, meta)
	ev.Metadata = map[string]string{
		"type":        "frame",
		"opcode":      opcodeNames[opcode],
		"fin":         boolStr(fin),
		"masked":      boolStr(masked),
		"payload_len": intStr(payloadLen),
	}
	return ev
}

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func intStr(n int) string {
	return strconv.Itoa(n)
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

var _ protocol.Parser = (*Parser)(nil)
