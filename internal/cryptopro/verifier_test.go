package cryptopro_test

import (
	"crypto-pro/internal/cryptopro"
	"crypto-pro/internal/domain"
	"crypto-pro/internal/testsupport"
	"crypto-pro/internal/validate"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

const (
	syntheticCMS  = "synthetic\x00cms-signature\xff"
	syntheticFile = "exact\x00signed-content\r\n\xff"
)

func TestAcceptsTheSingleEmbeddedCertificateFormatReturnedByCryptoPro(t *testing.T) {
	verifier := cryptopro.NewVerifier(cryptopro.Options{
		CryptcpPath:     testsupport.FakeCryptcp(t, testsupport.FakeCryptcpConfig{EmitSuccessMarker: true}),
		Timeout:         5 * time.Second,
		MaxContentBytes: validate.MaxContentBytes,
	})
	result, err := verifier.Verify(domain.TypeAttached, []byte(syntheticCMS), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.SignInfo == nil {
		t.Fatal("expected a valid signature")
	}
	if result.SignInfo.SHA1 != sha1Of(testsupport.LeafDER()) {
		t.Fatalf("sha1 %s", result.SignInfo.SHA1)
	}
}

func TestUsesOfflineChainValidationForDetachedBesSignatures(t *testing.T) {
	verifier := cryptopro.NewVerifier(cryptopro.Options{
		CryptcpPath:     testsupport.FakeCryptcp(t, testsupport.FakeCryptcpConfig{EmitSuccessMarker: true}),
		Timeout:         5 * time.Second,
		MaxContentBytes: validate.MaxContentBytes,
	})
	result, err := verifier.Verify(domain.TypeDetached, []byte(syntheticCMS), []byte(syntheticFile))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.SignInfo.SHA1 != sha1Of(testsupport.LeafDER()) {
		t.Fatal("detached BES verification failed")
	}
}

func TestKeepsInnleWhenOpensslReportsTheOidAsUndef(t *testing.T) {
	verifier := cryptopro.NewVerifier(cryptopro.Options{
		CryptcpPath: testsupport.FakeCryptcp(t, testsupport.FakeCryptcpConfig{
			EmitSuccessMarker: true,
			Certificate:       testsupport.InnleDER(),
		}),
		Timeout:         5 * time.Second,
		MaxContentBytes: validate.MaxContentBytes,
	})
	result, err := verifier.Verify(domain.TypeAttached, []byte(syntheticCMS), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.SignInfo == nil {
		t.Fatal("expected a valid signature")
	}
	assertPart(t, result.SignInfo.SubjectParts, "INNLE", "1234567890")
	assertPart(t, result.SignInfo.SubjectParts, "INN", "123456789012")
	assertPart(t, result.SignInfo.SubjectParts, "SNILS", "12345678901")
	assertPart(t, result.SignInfo.SubjectParts, "OGRN", "1234567890123")
	if !contains(result.SignInfo.Subject, "INNLE=1234567890") {
		t.Fatalf("subject %q", result.SignInfo.Subject)
	}
}

func TestRejectsProviderSuccessWithoutTheExactSuccessMarker(t *testing.T) {
	verifier := cryptopro.NewVerifier(cryptopro.Options{
		CryptcpPath:     testsupport.FakeCryptcp(t, testsupport.FakeCryptcpConfig{EmitSuccessMarker: false}),
		Timeout:         5 * time.Second,
		MaxContentBytes: validate.MaxContentBytes,
	})
	_, err := verifier.Verify(domain.TypeAttached, []byte(syntheticCMS), nil)
	assertFailure(t, err, domain.OutcomeUnknown)
}

func TestAppliesOneDeadlineAcrossCryptoProProcesses(t *testing.T) {
	verifier := cryptopro.NewVerifier(cryptopro.Options{
		CryptcpPath: testsupport.FakeCryptcp(t, testsupport.FakeCryptcpConfig{
			EmitSuccessMarker: true,
			DelayMilliseconds: 200,
		}),
		Timeout:         time.Second,
		Deadline:        50 * time.Millisecond,
		MaxContentBytes: validate.MaxContentBytes,
	})
	_, err := verifier.Verify(domain.TypeAttached, []byte(syntheticCMS), nil)
	assertFailure(t, err, domain.Timeout)
}

func TestFallsBackWhenErrchainReportsOfflineRevocation(t *testing.T) {
	verifier := cryptopro.NewVerifier(cryptopro.Options{
		CryptcpPath: testsupport.FakeCryptcp(t, testsupport.FakeCryptcpConfig{
			EmitSuccessMarker:  true,
			StaleCRLOnErrchain: true,
		}),
		Timeout:         5 * time.Second,
		Deadline:        45 * time.Second,
		AllowStaleCRL:   true,
		MaxContentBytes: validate.MaxContentBytes,
	})
	result, err := verifier.Verify(domain.TypeDetached, []byte(syntheticCMS), []byte(syntheticFile))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.SignInfo.SHA1 != sha1Of(testsupport.LeafDER()) {
		t.Fatal("stale CRL fallback failed")
	}
}

func TestDoesNotFallBackFromOfflineRevocationWhenDisabled(t *testing.T) {
	verifier := cryptopro.NewVerifier(cryptopro.Options{
		CryptcpPath: testsupport.FakeCryptcp(t, testsupport.FakeCryptcpConfig{
			EmitSuccessMarker:  true,
			StaleCRLOnErrchain: true,
		}),
		Timeout:         5 * time.Second,
		MaxContentBytes: validate.MaxContentBytes,
	})
	_, err := verifier.Verify(domain.TypeDetached, []byte(syntheticCMS), []byte(syntheticFile))
	assertFailure(t, err, domain.ProviderError)
}

func sha1Of(der []byte) string {
	sum := sha1.Sum(der)
	return hex.EncodeToString(sum[:])
}

func assertPart(t *testing.T, parts domain.NameParts, key, want string) {
	t.Helper()
	got, ok := parts.Get(key)
	if !ok || got != want {
		t.Fatalf("%s: got %q", key, got)
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

func assertFailure(t *testing.T, err error, want domain.Failure) {
	t.Helper()
	typed, ok := domain.AsError(err)
	if !ok {
		t.Fatalf("error %v", err)
	}
	if typed.Failure != want {
		t.Fatalf("failure %s want %s", typed.Failure, want)
	}
}
