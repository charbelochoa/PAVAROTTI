package analisis

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

type binaryReaderFunc func([]byte) (int, error)

func (read binaryReaderFunc) Read(data []byte) (int, error) { return read(data) }

func TestVerifiedBinaryChecksBlocksAndPreservesReadErrors(t *testing.T) {
	data := bytes.Repeat([]byte{0x81, 0x07, 0xf7}, 25000)
	digest := caso.Hash(data)
	verified, err := readVerifiedBinary(t.Context(), bytes.NewReader(data), len(data), digest)
	if err != nil || !bytes.Equal(data, verified) {
		t.Fatalf("original de varios bloques: %d bytes, %v", len(verified), err)
	}
	for _, input := range [][]byte{data[:len(data)-1], append(bytes.Clone(data), 0), nil} {
		if _, err := readVerifiedBinary(t.Context(), bytes.NewReader(input), len(data), digest); !errors.Is(err, ErrBinaryWindowSample) {
			t.Fatalf("longitud %d: %v", len(input), err)
		}
	}
	if _, err := readVerifiedBinary(t.Context(), bytes.NewReader(data), len(data), strings.Repeat("0", 64)); !errors.Is(err, ErrBinaryWindowSample) {
		t.Fatalf("huella incorrecta: %v", err)
	}
	first := data[:8]
	broken := errors.New("transmisión interrumpida")
	for _, readErr := range []error{io.EOF, broken} {
		calls := 0
		read := binaryReaderFunc(func(dst []byte) (int, error) {
			calls++
			return copy(dst, first), readErr
		})
		verified, err = readVerifiedBinary(t.Context(), read, len(first), caso.Hash(first))
		if calls != 1 || (readErr == io.EOF && (err != nil || !bytes.Equal(verified, first))) ||
			(readErr != io.EOF && !errors.Is(err, readErr)) {
			t.Fatalf("lector con %v: %d llamadas, %v", readErr, calls, err)
		}
	}
}

func TestVerifiedBinaryCancelsBeforeReadingRemainingBlocks(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	readBytes := 0
	reader := binaryReaderFunc(func(dst []byte) (int, error) {
		readBytes += len(dst)
		cancel()
		return len(dst), nil
	})
	data, err := readVerifiedBinary(ctx, reader, 1<<20, strings.Repeat("0", 64))
	if !errors.Is(err, context.Canceled) || readBytes != 64<<10 || data != nil {
		t.Fatalf("cancelación: %d bytes leídos, %v", readBytes, err)
	}
}

func TestMatchingReferenceMustCarryItsOriginalWindowHash(t *testing.T) {
	store, buffer, draft := binaryReferenceScale(t, 64, 64<<10)
	baseline := sealScaleReferences(t, store, buffer, draft)
	for _, alter := range []func([]BinaryReferenceLocation){
		func(rows []BinaryReferenceLocation) { rows[0].WindowSHA256 = strings.Repeat("0", 64) },
		func(rows []BinaryReferenceLocation) { rows[0] = rows[1] },
	} {
		current := baseline
		current.Origins = slices.Clone(current.Origins)
		alter(current.Origins)
		var err error
		current.ReportSHA256, err = binaryReferenceDigest(current)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CompareBinaryReferences(t.Context(), store, baseline, current, bytes.NewReader(buffer)); !errors.Is(err, ErrBinaryReferenceReport) {
			t.Fatalf("informe alterado: %v", err)
		}
	}
}
