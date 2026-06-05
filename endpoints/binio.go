// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package endpoints

import (
	"encoding/binary"
	"errors"
)

// Byte/word lengths for the wire formats this package emits.
const (
	ByteLen  = 1
	ShortLen = 2
	IntLen   = 4
	LongLen  = 8
)

// ErrInsufficientLength is returned by packer methods when the underlying byte
// slice can't satisfy the requested read/write.
var ErrInsufficientLength = errors.New("packer: insufficient length")

// packer is a thin big-endian byte-slice writer/reader. Self-contained for the
// fixed-shape wire layouts in this package (endpoint preimage, gossip ID
// preimage). No expansion semantics — callers size the slice up front.
type packer struct {
	Err    error
	Bytes  []byte
	Offset int
}

// PackByte writes a single byte at the current offset.
func (p *packer) PackByte(v byte) {
	if p.Err != nil {
		return
	}
	if p.Offset+ByteLen > len(p.Bytes) {
		p.Err = ErrInsufficientLength
		return
	}
	p.Bytes[p.Offset] = v
	p.Offset += ByteLen
}

// PackShort writes a big-endian uint16 at the current offset.
func (p *packer) PackShort(v uint16) {
	if p.Err != nil {
		return
	}
	if p.Offset+ShortLen > len(p.Bytes) {
		p.Err = ErrInsufficientLength
		return
	}
	binary.BigEndian.PutUint16(p.Bytes[p.Offset:], v)
	p.Offset += ShortLen
}

// PackLong writes a big-endian uint64 at the current offset.
func (p *packer) PackLong(v uint64) {
	if p.Err != nil {
		return
	}
	if p.Offset+LongLen > len(p.Bytes) {
		p.Err = ErrInsufficientLength
		return
	}
	binary.BigEndian.PutUint64(p.Bytes[p.Offset:], v)
	p.Offset += LongLen
}

// PackFixedBytes copies a fixed-size byte slice at the current offset.
func (p *packer) PackFixedBytes(b []byte) {
	if p.Err != nil {
		return
	}
	if p.Offset+len(b) > len(p.Bytes) {
		p.Err = ErrInsufficientLength
		return
	}
	copy(p.Bytes[p.Offset:], b)
	p.Offset += len(b)
}
