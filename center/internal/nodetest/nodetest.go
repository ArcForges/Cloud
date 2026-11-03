// SPDX-License-Identifier: AGPL-3.0-only

// Package nodetest is the MOCKED node of the center's tests (AF-CTR-04; the Plan task's fakes_allowed: "the Go node stand-ins
// center/internal/nodetest"): a node with a software ECDSA P-256 key and its own description, and a gRPC-Web client that calls the
// center over HTTP exactly as a node does, with a bearer credential when it has one. It is linked into test binaries only (no
// package of the center's executable imports it) and the Docker context excludes it, so it never reaches the image. It never claims
// an end-to-end result: the real node is the ArcForges CloudLink (parts N1, N2).
package nodetest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Node is a node's identity: its node ID, its key pair and how it describes itself.
type Node struct {
	ID        platform.ID
	Key       *ecdsa.PrivateKey
	PublicKey []byte
	Name      string
	Version   string
	OS        nodev1.OsFamily
	Arch      nodev1.CpuArchitecture
}

// New is a Linux x64 node named buildbox with a fresh node ID and key, reporting the .NET informational version with a commit.
func New() (*Node, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Node{ID: platform.NewID(), Key: key, PublicKey: der, Name: "buildbox", Version: "0.1.0-dev+15d6717144468ce0be615e8538f858d29b0fed7d",
		OS: nodev1.OsFamily_OS_FAMILY_LINUX, Arch: nodev1.CpuArchitecture_CPU_ARCHITECTURE_X64}, nil
}

// Info is the node's EnrollingNodeInfo.
func (n *Node) Info() *fleetv1.EnrollingNodeInfo {
	return &fleetv1.EnrollingNodeInfo{NodeId: &foundationv1.Id{Value: append([]byte(nil), n.ID[:]...)}, Name: proto.String(n.Name), Os: n.OS.Enum(),
		Arch: n.Arch.Enum(), Version: proto.String(n.Version)}
}

// Client calls a center's public listener.
type Client struct {
	// URL is the listener's base URL (the center's public base URL path is served at its root behind the Worker).
	URL string
	// ClientIP is the address the request states in the Worker's header; empty is 198.51.100.7.
	ClientIP string
	// ClientIPHeader is the header that carries it.
	ClientIPHeader string
}

// Reply is one gRPC-Web answer: the status trailer and the reply message, if any.
type Reply struct {
	Status  string
	Message string
	Body    []byte
	HTTP    int
}

// Post sends a request message to a method path with an optional bearer credential.
func (c Client) Post(path string, request proto.Message, bearer string) (Reply, error) {
	data, err := proto.Marshal(request)
	if err != nil {
		return Reply{}, err
	}
	frame := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(data)))
	copy(frame[5:], data)
	httpRequest, err := http.NewRequest(http.MethodPost, c.URL+path, bytes.NewReader(frame))
	if err != nil {
		return Reply{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/grpc-web+proto")
	address := c.ClientIP
	if address == "" {
		address = "198.51.100.7"
	}
	if c.ClientIPHeader != "" {
		httpRequest.Header.Set(c.ClientIPHeader, address)
	}
	if bearer != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(httpRequest)
	if err != nil {
		return Reply{}, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return Reply{}, err
	}
	result := Reply{HTTP: response.StatusCode}
	for position := 0; position+5 <= len(body); {
		flag, length := body[position], int(binary.BigEndian.Uint32(body[position+1:position+5]))
		if position+5+length > len(body) {
			return Reply{}, fmt.Errorf("a truncated gRPC-Web frame")
		}
		payload := body[position+5 : position+5+length]
		position += 5 + length
		if flag&0x80 != 0 {
			for _, line := range strings.Split(string(payload), "\r\n") {
				name, value, _ := strings.Cut(line, ":")
				switch strings.ToLower(strings.TrimSpace(name)) {
				case "grpc-status":
					result.Status = strings.TrimSpace(value)
				case "grpc-message":
					result.Message = strings.TrimSpace(value)
				}
			}
			continue
		}
		result.Body = payload
	}
	return result, nil
}

// Decode reads a completed reply's message.
func Decode[Response proto.Message](reply Reply, response Response) (Response, error) {
	if reply.Status != "0" || reply.Body == nil {
		return response, fmt.Errorf("grpc-status %q %q (HTTP %d)", reply.Status, reply.Message, reply.HTTP)
	}
	return response, proto.Unmarshal(reply.Body, response)
}
