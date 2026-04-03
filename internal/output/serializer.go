// Package output provides event serialization and Kafka-based output for
// captured network protocol events.
package output

import (
	"encoding/json"

	"github.com/netcap/netcap/proto"
)

// Serializer defines how a ProtocolEvent is encoded into bytes for transport.
type Serializer interface {
	// Marshal encodes the event into bytes.
	Marshal(event *proto.ProtocolEvent) ([]byte, error)
	// ContentType returns the MIME type of the serialized payload.
	ContentType() string
}

// JSONSerializer implements Serializer using encoding/json.
type JSONSerializer struct{}

// Marshal encodes the event as JSON.
func (s *JSONSerializer) Marshal(event *proto.ProtocolEvent) ([]byte, error) {
	return json.Marshal(event)
}

// ContentType returns the JSON MIME type.
func (s *JSONSerializer) ContentType() string {
	return "application/json"
}
