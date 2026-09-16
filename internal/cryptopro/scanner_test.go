package cryptopro_test

import (
	"crypto-pro/internal/cryptopro"
	"reflect"
	"testing"
)

func TestScannerAcceptsStandaloneSuccessLine(t *testing.T) {
	scanner := cryptopro.NewErrorCodeScanner()
	scanner.Consume([]byte("CryptoPro chatter\n[ErrorCode: 0x00000000]\n"))
	got := scanner.Codes()
	want := []string{"00000000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

func TestScannerAcceptsInvalidSignatureAndIgnoresCRLF(t *testing.T) {
	scanner := cryptopro.NewErrorCodeScanner()
	scanner.Consume([]byte("[ErrorCode: 0x200001F9]\r\n"))
	got := scanner.Codes()
	want := []string{"200001f9"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

func TestScannerTreatsEmbeddedMarkerAsMalformed(t *testing.T) {
	scanner := cryptopro.NewErrorCodeScanner()
	scanner.Consume([]byte("prefix ErrorCode: leaked\n[ErrorCode: 0x00000000]\n"))
	if scanner.Codes() != nil {
		t.Fatal("expected malformed output")
	}
}

func TestScannerTreatsTruncatedMarkerAsMalformed(t *testing.T) {
	scanner := cryptopro.NewErrorCodeScanner()
	scanner.Consume([]byte("[ErrorCode: 0x0000"))
	if scanner.Codes() != nil {
		t.Fatal("expected malformed output")
	}
}

func TestScannerEmptyStreamIsValidWithNoCodes(t *testing.T) {
	scanner := cryptopro.NewErrorCodeScanner()
	got := scanner.Codes()
	if got == nil || len(got) != 0 {
		t.Fatalf("empty stream should be valid and empty, got %#v", got)
	}
}

func TestScannerAcceptsMarkerAtEOFWithoutNewline(t *testing.T) {
	scanner := cryptopro.NewErrorCodeScanner()
	scanner.Consume([]byte("[ErrorCode: 0x00000000]"))
	got := scanner.Codes()
	want := []string{"00000000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}
