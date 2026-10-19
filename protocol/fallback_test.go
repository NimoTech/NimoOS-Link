package protocol

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	buf := make([]byte, MaxFrame)
	for _, n := range []int{1, 1420, MaxFrame} {
		p := bytes.Repeat([]byte{0xa5}, n)
		var w bytes.Buffer
		if err := WriteFrame(&w, p); err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if w.Len() != n+2 {
			t.Fatalf("%d: wrote %d bytes", n, w.Len())
		}
		got, err := ReadFrame(&w, buf)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("%d: got %d bytes, %v", n, len(got), err)
		}
	}
}

func TestWriteFrameRejects(t *testing.T) {
	var w bytes.Buffer
	if err := WriteFrame(&w, nil); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("empty: %v", err)
	}
	if err := WriteFrame(&w, make([]byte, MaxFrame+1)); !errors.Is(err, ErrFrameTooLong) {
		t.Fatalf("too long: %v", err)
	}
	if w.Len() != 0 {
		t.Fatalf("wrote %d bytes for refused frames", w.Len())
	}
}

func TestReadFrameZeroLength(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0}), make([]byte, MaxFrame)); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("got %v", err)
	}
}

func TestReadFrameTruncated(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 5, 1, 2}), make([]byte, MaxFrame)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0}), make([]byte, MaxFrame)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("half a length: got %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil), make([]byte, MaxFrame)); !errors.Is(err, io.EOF) {
		t.Fatalf("nothing: got %v", err)
	}
}
