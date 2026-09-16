package validate_test

import (
	"crypto-pro/internal/domain"
	"crypto-pro/internal/testsupport"
	"crypto-pro/internal/validate"
	"encoding/base64"
	"strings"
	"testing"
)

func TestExecuteRejectsNonCanonicalBase64(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{Result: domain.InvalidResult()}
	service := validate.NewService(verifier, true)
	_, err := service.Execute(domain.TypeAttached, "YQ", nil)
	if typed, ok := domain.AsError(err); !ok || typed.Failure != domain.InvalidSignatureInput {
		t.Fatalf("err %v", err)
	}
	if verifier.Calls != 0 {
		t.Fatal("verifier called")
	}
}

func TestExecuteStripsWhitespaceThenRequiresCanonicalAlphabet(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{Result: domain.InvalidResult()}
	service := validate.NewService(verifier, true)
	payload := []byte("hello")
	wrapped := chunk(base64.StdEncoding.EncodeToString(payload), 2, "\n")
	_, err := service.Execute(domain.TypeAttached, wrapped, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(verifier.Sign) != "hello" {
		t.Fatalf("got %q", verifier.Sign)
	}
}

func TestParseRequestRejectsExtraFields(t *testing.T) {
	_, err := validate.ParseRequest([]byte(`{"type":"attached","format":"bes","sign":"YQ==","x":1}`))
	if typed, ok := domain.AsError(err); !ok || typed.Failure != domain.InvalidSignatureInput {
		t.Fatalf("err %v", err)
	}
}

func chunk(s string, n int, sep string) string {
	var b strings.Builder
	for len(s) > 0 {
		if n > len(s) {
			n = len(s)
		}
		b.WriteString(s[:n])
		b.WriteString(sep)
		s = s[n:]
	}
	return b.String()
}
