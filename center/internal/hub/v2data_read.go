// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

var errNodeFrameTooLarge = errors.New("node channel frame exceeds its bound")

func (c *conn) readNodeFrame(reader io.Reader, binaryFrame bool) ([]byte, error) {
	limit := c.hub.settings.MaxFrameBytes
	if binaryFrame && c.v2 != nil {
		var header [v2HeaderBytes]byte
		n, err := io.ReadFull(reader, header[:])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return header[:n], nil
		}
		if err != nil {
			return nil, err
		}
		if header[0] == v2Version && header[1] == v2DataResultKind {
			return c.readV2DataResult(reader, header)
		}
		reader = io.MultiReader(bytes.NewReader(header[:]), reader)
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err == nil && len(data) > limit {
		return nil, errNodeFrameTooLarge
	}
	return data, err
}

// A data result has no selector on its wire. Look up the exact already-sent call
// and compare its binding before allocating or reading a potentially larger body.
func (c *conn) readV2DataResult(reader io.Reader, header [v2HeaderBytes]byte) ([]byte, error) {
	if c.v2.inboundSeq == math.MaxUint64 || binary.BigEndian.Uint64(header[2:]) != c.v2.inboundSeq+1 {
		return nil, errFrame
	}
	var prefix [v2ControlResultLengthOffset + 4]byte
	if err := readExactDataResult(reader, prefix[:]); err != nil {
		return nil, err
	}
	id := platform.ID(prefix[:v2ControlIDSize])
	binding := [sha256.Size]byte(prefix[v2ControlIDSize:v2ControlResultLengthOffset])
	limit := c.v2DataResultLimit(id, binding)
	if limit == 0 {
		return nil, errFrame
	}
	declared := binary.BigEndian.Uint32(prefix[v2ControlResultLengthOffset:])
	if declared == 0 {
		return nil, errFrame
	}
	if declared > v2DataMaxBody || !v2ControlFrameFits(limit, v2ControlResultFixed, int(declared)) {
		return nil, errNodeFrameTooLarge
	}
	frame := make([]byte, v2HeaderBytes+v2ControlResultFixed+int(declared)+v2SignatureSize)
	copy(frame, header[:])
	copy(frame[v2HeaderBytes:], prefix[:])
	if err := readExactDataResult(reader, frame[v2HeaderBytes+len(prefix):]); err != nil {
		return nil, err
	}
	var trailing [1]byte
	_, err := io.ReadFull(reader, trailing[:])
	if errors.Is(err, io.EOF) {
		return frame, nil
	}
	if err == nil {
		return nil, errFrame
	}
	return nil, err
}

func readExactDataResult(reader io.Reader, target []byte) error {
	_, err := io.ReadFull(reader, target)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errFrame
	}
	return err
}

func (c *conn) v2DataResultLimit(id platform.ID, binding [sha256.Size]byte) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.v2Ready || c.callsClosed || c.closing.Load() || id == (platform.ID{}) ||
		!c.capabilities[v2ControlCapability] || !c.capabilities[v2StreamDataCapability] {
		return 0
	}
	p, late, selector, expected := c.v2ControlResultTargetLocked(id)
	if (p == nil || !p.started) && late < 0 || !selector.data() || expected != binding {
		return 0
	}
	return selector.resultLimit(c.hub.settings.MaxFrameBytes)
}
