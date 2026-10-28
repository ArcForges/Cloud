// SPDX-License-Identifier: AGPL-3.0-only

package ingress

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// The gRPC-Web wire framing the pipeline reads and writes itself: one flag byte, a big-endian length and the payload. A gRPC
// message on HTTP/2 uses the same five-byte prefix.
const (
	DataFlag     = 0x00
	TrailerFlag  = 0x80
	HeaderLength = 5
)

// Status is a gRPC status code.
type Status int

// The gRPC status codes the pipeline itself produces.
const (
	StatusOK                 Status = 0
	StatusCanceled           Status = 1
	StatusInvalidArgument    Status = 3
	StatusDeadlineExceeded   Status = 4
	StatusPermissionDenied   Status = 7
	StatusResourceExhausted  Status = 8
	StatusFailedPrecondition Status = 9
	StatusUnimplemented      Status = 12
	StatusInternal           Status = 13
	StatusUnavailable        Status = 14
	StatusUnauthenticated    Status = 16
)

// Frame is one uncompressed data frame carrying message.
func Frame(message []byte) []byte {
	frame := make([]byte, HeaderLength+len(message))
	frame[0] = DataFlag
	binary.BigEndian.PutUint32(frame[1:], uint32(len(message)))
	copy(frame[HeaderLength:], message)
	return frame
}

// TrailerFrame is a gRPC-Web trailer frame: one "name: value" CRLF line per trailer, names already lowercase, the message
// percent-encoded as the C# host encodes it (Uri.EscapeDataString). It is byte-for-byte the frame of the C# host.
func TrailerFrame(status Status, message string, hasMessage bool, extra ...[2]string) []byte {
	var text strings.Builder
	text.WriteString("grpc-status: ")
	text.WriteString(strconv.Itoa(int(status)))
	text.WriteString("\r\n")
	if hasMessage {
		text.WriteString("grpc-message: ")
		text.WriteString(EscapeDataString(message))
		text.WriteString("\r\n")
	}
	for _, trailer := range extra {
		text.WriteString(trailer[0])
		text.WriteString(": ")
		text.WriteString(trailer[1])
		text.WriteString("\r\n")
	}
	payload := text.String()
	frame := make([]byte, HeaderLength+len(payload))
	frame[0] = TrailerFlag
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	copy(frame[HeaderLength:], payload)
	return frame
}

// ReadSingleMessage is the one message of a unary or server-streaming request: exactly one uncompressed data frame whose
// declared length matches the rest of the body. Anything else (no frame, a second frame, the compressed flag, a trailer flag,
// a length mismatch) is refused.
func ReadSingleMessage(body []byte) ([]byte, bool) {
	if len(body) < HeaderLength || body[0] != DataFlag {
		return nil, false
	}
	if uint64(binary.BigEndian.Uint32(body[1:])) != uint64(len(body)-HeaderLength) {
		return nil, false
	}
	return body[HeaderLength:], true
}

// EscapeDataString percent-encodes every UTF-8 byte except the RFC 3986 unreserved characters (letters, digits, "-", ".",
// "_" and "~") with uppercase hexadecimal digits, as .NET's Uri.EscapeDataString does.
func EscapeDataString(value string) string {
	const digits = "0123456789ABCDEF"
	var text strings.Builder
	for index := range len(value) {
		b := value[index]
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~' {
			text.WriteByte(b)
			continue
		}
		text.WriteByte('%')
		text.WriteByte(digits[b>>4])
		text.WriteByte(digits[b&15])
	}
	return text.String()
}
