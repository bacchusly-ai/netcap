// Package http implements an HTTP/1.x protocol parser.
package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

const (
	// connStateTTL bounds how long per-connection counter state lives after
	// the last seen message. The reassembly engine's max_connection_age is
	// 10 minutes by default; we keep parser state a touch longer so the
	// final response's UID still matches its request.
	connStateTTL = 15 * time.Minute
	// connStateGCInterval controls how often the janitor sweeps for expired
	// per-connection state.
	connStateGCInterval = 1 * time.Minute
)

// connState tracks per-connection FIFO counters for request/response pairing.
// HTTP/1.x keep-alive guarantees responses arrive in the same order as their
// requests, so independent counters on each direction stay aligned.
type connState struct {
	reqSeq       atomic.Uint64
	respSeq      atomic.Uint64
	lastActivity atomic.Int64 // unix-nanos
}

// Parser detects and decodes HTTP/1.x traffic.
type Parser struct {
	maxBodyBytes int

	connStates sync.Map // map[uint64]*connState

	gcOnce sync.Once
	gcStop chan struct{}
}

var _ protocol.Parser = (*Parser)(nil)

// NewParser constructs an HTTP parser. maxBodyBytes caps the number of body
// bytes captured per message; 0 disables body capture entirely.
func NewParser(maxBodyBytes int) *Parser {
	if maxBodyBytes < 0 {
		maxBodyBytes = 0
	}
	p := &Parser{
		maxBodyBytes: maxBodyBytes,
		gcStop:       make(chan struct{}),
	}
	return p
}

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

// Parse decodes the raw payload into ProtocolEvents. A single buffer may
// contain multiple pipelined or keep-alive messages; we read until the
// reader is exhausted or a parse error halts progress.
func (p *Parser) Parse(data []byte, meta protocol.ConnMeta, isFromClient bool) ([]*proto.ProtocolEvent, error) {
	p.gcOnce.Do(func() { go p.gcLoop() })

	state := p.stateFor(meta.ConnID)
	state.lastActivity.Store(time.Now().UnixNano())

	reader := bufio.NewReader(bytes.NewReader(data))
	events := make([]*proto.ProtocolEvent, 0, 1)

	for {
		var (
			ev  *proto.ProtocolEvent
			err error
		)
		if isFromClient {
			ev, err = p.readRequest(reader, meta, state)
		} else {
			ev, err = p.readResponse(reader, meta, state)
		}
		if err != nil {
			// After at least one full message, any error means the buffer ended
			// on a partial follow-up — normal and not worth surfacing.
			if len(events) > 0 {
				return events, nil
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, nil
			}
			return nil, fmt.Errorf("http: parse: %w", err)
		}
		events = append(events, ev)
	}
}

// stateFor returns the per-connection counter state, creating it on first
// access. UDP/zero ConnID falls into a shared bucket — uncommon for HTTP.
func (p *Parser) stateFor(connID uint64) *connState {
	if v, ok := p.connStates.Load(connID); ok {
		return v.(*connState)
	}
	fresh := &connState{}
	v, _ := p.connStates.LoadOrStore(connID, fresh)
	return v.(*connState)
}

func (p *Parser) readRequest(reader *bufio.Reader, meta protocol.ConnMeta, state *connState) (*proto.ProtocolEvent, error) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()

	body, truncated := p.readBody(req.Body)

	ev := proto.NewEvent("http", proto.DirectionRequest)
	ev.UID = p.makeUID(meta.ConnID, state.reqSeq.Add(1)-1)
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)

	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}

	ev.HTTPDetail = &proto.HTTPDetail{
		Method:        req.Method,
		URL:           req.RequestURI,
		Host:          host,
		Headers:       flattenHeader(req.Header),
		ContentType:   req.Header.Get("Content-Type"),
		BodyLength:    req.ContentLength,
		Body:          body,
		BodyTruncated: truncated,
	}
	return ev, nil
}

func (p *Parser) readResponse(reader *bufio.Reader, meta protocol.ConnMeta, state *connState) (*proto.ProtocolEvent, error) {
	// We don't have the original request — pass nil. http.ReadResponse handles
	// this by treating the response as if for a GET.
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, truncated := p.readBody(resp.Body)

	contentLength := resp.ContentLength
	if contentLength < 0 {
		// ContentLength is -1 when unknown; try the header directly.
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
				contentLength = n
			}
		}
	}

	ev := proto.NewEvent("http", proto.DirectionResponse)
	ev.UID = p.makeUID(meta.ConnID, state.respSeq.Add(1)-1)
	ev.SrcIP = meta.SrcIP
	ev.DstIP = meta.DstIP
	ev.SrcPort = uint32(meta.SrcPort)
	ev.DstPort = uint32(meta.DstPort)
	ev.HTTPDetail = &proto.HTTPDetail{
		StatusCode:    int32(resp.StatusCode),
		Headers:       flattenHeader(resp.Header),
		ContentType:   resp.Header.Get("Content-Type"),
		BodyLength:    contentLength,
		Body:          body,
		BodyTruncated: truncated,
	}
	return ev, nil
}

// readBody pulls up to maxBodyBytes from r and reports whether truncation
// occurred. The body reader is always drained (or one byte past the limit
// is consumed) so the bufio.Reader is positioned at the next message.
func (p *Parser) readBody(r io.Reader) ([]byte, bool) {
	if p.maxBodyBytes == 0 {
		_, _ = io.Copy(io.Discard, r)
		return nil, false
	}
	limited := io.LimitReader(r, int64(p.maxBodyBytes)+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		// Partial body is still useful for downstream consumers.
		if len(buf) > p.maxBodyBytes {
			return buf[:p.maxBodyBytes], true
		}
		return buf, false
	}
	if len(buf) > p.maxBodyBytes {
		// Drain the remainder so the framed reader advances cleanly.
		_, _ = io.Copy(io.Discard, r)
		return buf[:p.maxBodyBytes], true
	}
	return buf, false
}

func (p *Parser) makeUID(connID, seq uint64) string {
	return fmt.Sprintf("%016x-%d", connID, seq)
}

func flattenHeader(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// gcLoop evicts per-connection state that has been idle past connStateTTL.
func (p *Parser) gcLoop() {
	ticker := time.NewTicker(connStateGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.gcStop:
			return
		case now := <-ticker.C:
			cutoff := now.Add(-connStateTTL).UnixNano()
			p.connStates.Range(func(k, v any) bool {
				s := v.(*connState)
				if s.lastActivity.Load() < cutoff {
					p.connStates.Delete(k)
				}
				return true
			})
		}
	}
}

// OnConnClose drops per-connection counter state when the underlying TCP
// connection has ended. Without this hook, a 5-tuple reused within the
// TTL window would inherit stale request/response counters from the
// previous connection — which, combined with any packet loss, can cause
// false request/response pairing via UID.
func (p *Parser) OnConnClose(connID uint64) {
	p.connStates.Delete(connID)
}

// Close stops the GC goroutine. Safe to call multiple times.
func (p *Parser) Close() {
	select {
	case <-p.gcStop:
	default:
		close(p.gcStop)
	}
}
