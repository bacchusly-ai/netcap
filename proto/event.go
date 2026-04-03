// Package proto defines hand-written Go structs that mirror the intended
// protobuf schema for network capture events. JSON tags are provided so the
// structs can be serialized with encoding/json today; a future migration to
// real protobuf-generated code should be a drop-in replacement.
package proto

import "time"

// Direction indicates whether the captured packet/message is a request,
// a response, or unknown.
type Direction int

const (
	DirectionUnknown  Direction = 0
	DirectionRequest  Direction = 1
	DirectionResponse Direction = 2
)

// ProtocolEvent is the top-level envelope for every captured protocol event.
type ProtocolEvent struct {
	TimestampNs int64             `json:"timestamp_ns"`
	SrcIP       []byte            `json:"src_ip"`
	DstIP       []byte            `json:"dst_ip"`
	SrcPort     uint32            `json:"src_port"`
	DstPort     uint32            `json:"dst_port"`
	Protocol    string            `json:"protocol"`
	Direction   Direction         `json:"direction"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	RawExcerpt  []byte            `json:"raw_excerpt,omitempty"`
	HTTPDetail  *HTTPDetail       `json:"http_detail,omitempty"`
	DNSDetail   *DNSDetail        `json:"dns_detail,omitempty"`
	TLSDetail   *TLSDetail        `json:"tls_detail,omitempty"`
	DBDetail    *DBDetail         `json:"db_detail,omitempty"`
}

// NewEvent creates a ProtocolEvent pre-filled with the current wall-clock
// timestamp, the given protocol name, and direction.
func NewEvent(protocol string, dir Direction) *ProtocolEvent {
	return &ProtocolEvent{
		TimestampNs: time.Now().UnixNano(),
		Protocol:    protocol,
		Direction:   dir,
	}
}

// ---------------------------------------------------------------------------
// Protocol-specific detail structs
// ---------------------------------------------------------------------------

// HTTPDetail carries parsed HTTP request/response fields.
type HTTPDetail struct {
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	Host        string            `json:"host,omitempty"`
	StatusCode  int32             `json:"status_code,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	BodyLength  int64             `json:"body_length,omitempty"`
}

// DNSDetail carries parsed DNS query/response fields.
type DNSDetail struct {
	TransactionID uint16        `json:"transaction_id,omitempty"`
	OpCode        int32         `json:"op_code,omitempty"`
	ResponseCode  int32         `json:"response_code,omitempty"`
	Questions     []DNSQuestion `json:"questions,omitempty"`
	Answers       []DNSAnswer   `json:"answers,omitempty"`
}

// DNSQuestion represents a single DNS question entry.
type DNSQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

// DNSAnswer represents a single DNS resource record in the answer section.
type DNSAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

// TLSDetail carries parsed TLS handshake metadata.
type TLSDetail struct {
	Version          string   `json:"version,omitempty"`
	CipherSuite      string   `json:"cipher_suite,omitempty"`
	ServerName       string   `json:"server_name,omitempty"`
	HandshakeType    int32    `json:"handshake_type,omitempty"`
	CertificateChain []string `json:"certificate_chain,omitempty"`
	ALPNProtocols    []string `json:"alpn_protocols,omitempty"`
}

// DBDetail carries parsed database protocol (MySQL, PostgreSQL, etc.) fields.
type DBDetail struct {
	System    string `json:"system,omitempty"`
	Operation string `json:"operation,omitempty"`
	Statement string `json:"statement,omitempty"`
	Database  string `json:"database,omitempty"`
	Table     string `json:"table,omitempty"`
	ErrorCode int32  `json:"error_code,omitempty"`
	ErrorMsg  string `json:"error_msg,omitempty"`
	Latency   int64  `json:"latency,omitempty"`
	RowCount  int64  `json:"row_count,omitempty"`
}
