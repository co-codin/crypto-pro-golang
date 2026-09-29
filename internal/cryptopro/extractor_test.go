package cryptopro_test

import (
	"crypto-pro/internal/cryptopro"
	"crypto-pro/internal/domain"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExtractsRsaTestingCMSCertificate(t *testing.T) {
	cms := loadAttachedCMS(t)
	certs, err := cryptopro.NewCMSExtractor().Extract(cms)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certificates", len(certs))
	}
	if _, ok := certs["193db102ca50b57c47f1afbbb6c5bc4c71d09c2b"]; !ok {
		t.Fatalf("missing expected fingerprint, got %v", keys(certs))
	}
}

func TestRejectsNonCMSPayload(t *testing.T) {
	_, err := cryptopro.NewCMSExtractor().Extract([]byte("synthetic\x00cms-signature"))
	assertFailure(t, err, domain.InvalidSignatureStructure)
}

func TestSyntheticVerifierReadsAttachedSample(t *testing.T) {
	cms := loadAttachedCMS(t)
	result, err := cryptopro.NewSyntheticVerifier().Verify(domain.TypeAttached, cms, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.SignInfo == nil {
		t.Fatal("expected synthetic success")
	}
	if result.SignInfo.SHA1 != "193db102ca50b57c47f1afbbb6c5bc4c71d09c2b" {
		t.Fatalf("sha1 %s", result.SignInfo.SHA1)
	}
}

func loadAttachedCMS(t *testing.T) []byte {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "signatures", "attached.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Sign string `json:"sign"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	cms, err := base64.StdEncoding.DecodeString(payload.Sign)
	if err != nil {
		t.Fatal(err)
	}
	return cms
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
