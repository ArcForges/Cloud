// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"
)

// grpcWeb sends one unary binary gRPC-Web request and decodes the first data frame of its reply into response (the center answers a
// domain refusal as a reply message carrying its ArcError, with the OK status trailer).
func grpcWeb(address string, request, response proto.Message) error {
	data, err := proto.Marshal(request)
	if err != nil {
		return err
	}
	frame := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(data)))
	copy(frame[5:], data)
	httpRequest, err := http.NewRequest(http.MethodPost, address, bytes.NewReader(frame))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/grpc-web+proto")
	httpRequest.Header.Set("X-Grpc-Web", "1")
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	reply, err := client.Do(httpRequest)
	if err != nil {
		return err
	}
	defer reply.Body.Close()
	body, err := io.ReadAll(io.LimitReader(reply.Body, 1<<20))
	if err != nil {
		return err
	}
	if reply.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", reply.StatusCode)
	}
	for len(body) >= 5 {
		flags, length := body[0], binary.BigEndian.Uint32(body[1:5])
		if uint64(len(body)-5) < uint64(length) {
			return errors.New("a truncated frame")
		}
		if flags&0x80 == 0 {
			return proto.Unmarshal(body[5:5+length], response)
		}
		body = body[5+length:]
	}
	if status := reply.Header.Get("Grpc-Status"); status != "" && status != "0" {
		return fmt.Errorf("gRPC status %s", status)
	}
	return errors.New("no reply message")
}
