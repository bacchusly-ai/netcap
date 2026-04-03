// Package http implements an HTTP/1.x protocol parser.
package http

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/netcap/netcap/internal/protocol"
	"github.com/netcap/netcap/proto"
)

// well-known HTTP method prefixes used for probing.
var httpPrefixes = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("PATCH "),
	[]byte("OPTIONS "),
	[]byte("HTTP/"),
}

// Parser detects and decodes HTTP/1.x traffic.
type Parser struct{}

var _ protocol.Parser = (*Parser)(nil)

// Name returns the protocol identifier.
func (p *Parser) Name() string { return "http" }

// Ports returns well-known HTTP ports.
func (p *Parser) Ports() []uint16 {
	return []uint16{80, 8080, 8000, 8888, 3000}
}

// Probe checks whether data begins with a known HTTP method or status line.
// Returns a confidence score between 0 and 100.
func (p *Parser) Probe(data []byte, isFromClient bool) int {
	for _, prefix := range httpPrefixes {
		if bytes.HasPrefix(data, prefix) {
			return 90
		}
	}
	return 0
}

// Parse decodes the raw payload into ProtocolEvents.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	if isFromClient {
		return p.parseRequest(data, meta)
	}
	return p.parseResponse(data, meta)
}

// parseRequest reads an HTTP request from the payload.
func (p *Parser) parseRequest(data []byte, meta protocol.ConnMeta) ([]*proto.ProtocolEvent, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, fmt.Errorf("http: read request: %w", err)
	}
	defer req.Body.Close()

	ev := proto.NewEvent("http", proto.DirectionRequest)
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)

	headers := make(map[string]string, len(req.Header))
	for k, v := range req.Header {
		headers[k] = strings.Join(v, ", ")
	}

	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}

	ev.HTTPDetail = &proto.HTTPDetail{
		Method:      req.Method,
		URL:         req.RequestURI,
		Host:        host,
		Headers:     headers,
		ContentType: req.Header.Get("Content-Type"),
		BodyLength:  req.ContentLength,
	}

	return []*proto.ProtocolEvent{ev}, nil
}

// parseResponse reads an HTTP response from the payload.
func (p *Parser) parseResponse(data []byte, meta protocol.ConnMeta) ([]*proto.ProtocolEvent, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	// We don't have the original request, pass nil.
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, fmt.Errorf("http: read response: %w", err)
	}
	defer resp.Body.Close()

	ev := proto.NewEvent("http", proto.DirectionResponse)
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}

	contentLength := resp.ContentLength
	if contentLength < 0 {
		// ContentLength is -1 when unknown; try the header directly.
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
				contentLength = n
			}
		}
	}

	ev.HTTPDetail = &proto.HTTPDetail{
		StatusCode:  int32(resp.StatusCode),
		Headers:     headers,
		ContentType: resp.Header.Get("Content-Type"),
		BodyLength:  contentLength,
	}

	return []*proto.ProtocolEvent{ev}, nil
}
