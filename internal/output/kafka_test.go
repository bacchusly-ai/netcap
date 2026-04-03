package output

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"

	"github.com/netcap/netcap/proto"
)

// TestFlowKeyConsistency verifies that the same 5-tuple always produces
// the same flow key, and different tuples produce different keys.
func TestFlowKeyConsistency(t *testing.T) {
	ev := &proto.ProtocolEvent{
		SrcIP:   net.ParseIP("10.0.0.1").To4(),
		DstIP:   net.ParseIP("10.0.0.2").To4(),
		SrcPort: 12345,
		DstPort: 80,
	}

	key1 := FlowKey(ev)
	key2 := FlowKey(ev)
	if !bytes.Equal(key1, key2) {
		t.Fatalf("flow key not consistent: %x vs %x", key1, key2)
	}

	// Different source port must yield a different key.
	ev2 := &proto.ProtocolEvent{
		SrcIP:   net.ParseIP("10.0.0.1").To4(),
		DstIP:   net.ParseIP("10.0.0.2").To4(),
		SrcPort: 54321,
		DstPort: 80,
	}
	key3 := FlowKey(ev2)
	if bytes.Equal(key1, key3) {
		t.Fatal("different 5-tuples produced the same flow key")
	}
}

// TestFlowKeyLength ensures the key is always 8 bytes (uint64).
func TestFlowKeyLength(t *testing.T) {
	ev := &proto.ProtocolEvent{
		SrcIP:   net.ParseIP("192.168.1.1").To4(),
		DstIP:   net.ParseIP("192.168.1.2").To4(),
		SrcPort: 443,
		DstPort: 8080,
	}
	key := FlowKey(ev)
	if len(key) != 8 {
		t.Fatalf("expected 8-byte key, got %d bytes", len(key))
	}
}

// TestJSONSerializerRoundTrip verifies that JSONSerializer produces valid
// JSON that can be unmarshalled back into a ProtocolEvent.
func TestJSONSerializerRoundTrip(t *testing.T) {
	original := proto.NewEvent("HTTP", proto.DirectionRequest)
	original.SrcIP = net.ParseIP("10.0.0.1").To4()
	original.DstIP = net.ParseIP("10.0.0.2").To4()
	original.SrcPort = 12345
	original.DstPort = 80
	original.HTTPDetail = &proto.HTTPDetail{
		Method:     "GET",
		URL:        "/api/v1/health",
		Host:       "example.com",
		StatusCode: 200,
	}
	original.Metadata = map[string]string{"env": "test"}

	s := &JSONSerializer{}
	data, err := s.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded proto.ProtocolEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.Protocol != "HTTP" {
		t.Errorf("protocol mismatch: got %q, want %q", decoded.Protocol, "HTTP")
	}
	if decoded.SrcPort != 12345 {
		t.Errorf("src_port mismatch: got %d, want %d", decoded.SrcPort, 12345)
	}
	if decoded.HTTPDetail == nil {
		t.Fatal("http_detail is nil after round-trip")
	}
	if decoded.HTTPDetail.Method != "GET" {
		t.Errorf("http method mismatch: got %q, want %q", decoded.HTTPDetail.Method, "GET")
	}
}

// TestJSONSerializerContentType checks the MIME type string.
func TestJSONSerializerContentType(t *testing.T) {
	s := &JSONSerializer{}
	if ct := s.ContentType(); ct != "application/json" {
		t.Errorf("content type: got %q, want %q", ct, "application/json")
	}
}
