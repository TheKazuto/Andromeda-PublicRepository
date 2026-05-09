// Package policies wires Andromeda's Quasar policy templates into the
// gateway: template registry, instruction encoders, PDA derivation, REST
// endpoints. Adapters live here (NOT in ika-backend) so engines remain
// product-agnostic.
package policies

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ByteWriter is a minimal little-endian writer; the Quasar wire format is
// LE everywhere except `[u8; N]` arrays (raw bytes).
type ByteWriter struct{ buf bytes.Buffer }

func (w *ByteWriter) U8(v uint8)           { w.buf.WriteByte(v) }
func (w *ByteWriter) U16(v uint16)         { _ = binary.Write(&w.buf, binary.LittleEndian, v) }
func (w *ByteWriter) U32(v uint32)         { _ = binary.Write(&w.buf, binary.LittleEndian, v) }
func (w *ByteWriter) U64(v uint64)         { _ = binary.Write(&w.buf, binary.LittleEndian, v) }
func (w *ByteWriter) I64(v int64)          { _ = binary.Write(&w.buf, binary.LittleEndian, v) }
func (w *ByteWriter) Bytes(b []byte)       { w.buf.Write(b) }
func (w *ByteWriter) Bytes32(b [32]byte)   { w.buf.Write(b[:]) }
func (w *ByteWriter) Result() []byte       { return w.buf.Bytes() }

// VecBytes32 encodes Vec<[u8; 32], MAX>.
func (w *ByteWriter) VecBytes32(items [][32]byte) {
	w.U32(uint32(len(items)))
	for _, it := range items {
		w.buf.Write(it[:])
	}
}

func ToFixed32(b []byte) ([32]byte, error) {
	var out [32]byte
	if len(b) != 32 {
		return out, errors.New("expected 32 bytes")
	}
	copy(out[:], b)
	return out, nil
}
