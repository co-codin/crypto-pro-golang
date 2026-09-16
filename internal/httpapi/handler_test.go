package httpapi_test

import (
	"bytes"
	"crypto-pro/internal/domain"
	"crypto-pro/internal/httpapi"
	"crypto-pro/internal/testsupport"
	"crypto-pro/internal/validate"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

const (
	endpoint        = "/api/crypto/v1/validate"
	syntheticCMS    = "synthetic\x00cms-signature\xff"
	syntheticFile   = "exact\x00signed-content\r\n\xff"
	guidPattern     = `\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z`
	invalidJSON     = `{"error":{"code":400,"message":"Invalid signature validation request."}}`
	invalidSignJSON = `{"isSignValid":false,"error":{"code":"0x200001F9","message":"The signature is invalid."}}`
)

func sampleSignInfo() domain.CertificateInfo {
	issuer := domain.NewNameParts()
	issuer.Set("CN", "Test CA")
	issuer.Set("O", "Example Org")
	subject := domain.NewNameParts()
	subject.Set("CN", "Test Signer")
	subject.Set("O", "Example Org")
	subject.Set("SN", "Doe")
	subject.Set("G", "Jane")
	return domain.CertificateInfo{
		Issuer:       issuer.String(),
		IssuerParts:  issuer,
		Subject:      subject.String(),
		SubjectParts: subject,
		Serial:       "123456789",
		HexSerial:    "075BCD15",
		SHA1:         "0123456789abcdef0123456789abcdef01234567",
		ValidFrom:    "2026-01-01T00:00:00+00:00",
		ValidTo:      "2027-01-01T00:00:00+00:00",
		SubjectKeyID: "89abcdef0123456789abcdef0123456789abcdef",
	}
}

func newAPI(t *testing.T, verifier *testsupport.RecordingVerifier) (*httptest.Server, *testsupport.RecordingHandler) {
	t.Helper()
	logs := &testsupport.RecordingHandler{}
	logger := slog.New(logs)
	service := validate.NewService(verifier, true)
	handler := httpapi.NewHandler(service, logger)
	server := httptest.NewServer(httpapi.NewServer("", handler).Handler)
	t.Cleanup(server.Close)
	return server, logs
}

func postJSON(t *testing.T, server *httptest.Server, body any) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+endpoint, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer contract-backend-guid")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertGUID(t *testing.T, resp *http.Response) string {
	t.Helper()
	guid := resp.Header.Get("X-Guid")
	if !regexp.MustCompile(guidPattern).MatchString(guid) {
		t.Fatalf("X-Guid %q does not match UUID v4", guid)
	}
	return guid
}

func TestValidatesAnAttachedSignatureUsingTheClientContract(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{Result: domain.ValidResult(sampleSignInfo())}
	server, _ := newAPI(t, verifier)

	resp := postJSON(t, server, map[string]any{
		"type":   "attached",
		"format": "bes",
		"sign":   base64.StdEncoding.EncodeToString([]byte(syntheticCMS)),
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type %q", ct)
	}
	assertGUID(t, resp)
	expected, _ := json.Marshal(map[string]any{"isSignValid": true, "signInfo": sampleSignInfo()})
	assertJSONEqual(t, string(expected), body)
	if verifier.Calls != 1 || verifier.Type != domain.TypeAttached {
		t.Fatalf("verifier calls=%d type=%s", verifier.Calls, verifier.Type)
	}
	if string(verifier.Sign) != syntheticCMS || verifier.File != nil {
		t.Fatalf("verifier received unexpected bytes")
	}
}

func TestPassesExactDetachedFileBytesToTheVerifier(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{Result: domain.ValidResult(sampleSignInfo())}
	server, _ := newAPI(t, verifier)

	resp := postJSON(t, server, map[string]any{
		"type":   "detached",
		"format": "bes",
		"sign":   base64.StdEncoding.EncodeToString([]byte(syntheticCMS)),
		"file":   base64.StdEncoding.EncodeToString([]byte(syntheticFile)),
	})
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if verifier.Calls != 1 || verifier.Type != domain.TypeDetached {
		t.Fatalf("verifier calls=%d type=%s", verifier.Calls, verifier.Type)
	}
	if string(verifier.Sign) != syntheticCMS || string(verifier.File) != syntheticFile {
		t.Fatalf("detached bytes were not passed through exactly")
	}
}

func TestAcceptsWrappedBase64FromBrowserPlugins(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{Result: domain.ValidResult(sampleSignInfo())}
	server, _ := newAPI(t, verifier)

	resp := postJSON(t, server, map[string]any{
		"type":   "detached",
		"format": "bes",
		"sign":   testsupport.WrapBase64([]byte(syntheticCMS), 4, "\n"),
		"file":   testsupport.WrapBase64([]byte(syntheticFile), 8, "\r\n"),
	})
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if string(verifier.Sign) != syntheticCMS || string(verifier.File) != syntheticFile {
		t.Fatalf("wrapped base64 was not decoded to the original bytes")
	}
}

func TestReturnsTheLegacyInvalidSignatureResult(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{Result: domain.InvalidResult()}
	server, _ := newAPI(t, verifier)

	resp := postJSON(t, server, map[string]any{
		"type":   "attached",
		"format": "bes",
		"sign":   base64.StdEncoding.EncodeToString([]byte(syntheticCMS)),
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	assertJSONEqual(t, invalidSignJSON, body)
	if resp.Header.Get("X-Guid") == "" {
		t.Fatal("missing X-Guid")
	}
}

func TestRejectsMalformedJSONBeforeCallingCryptoPro(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{Result: domain.ValidResult(sampleSignInfo())}
	server, _ := newAPI(t, verifier)

	req, _ := http.NewRequest(http.MethodPost, server.URL+endpoint, strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if verifier.Calls != 0 {
		t.Fatalf("verifier was called %d times", verifier.Calls)
	}
}

func TestRejectsNonJSONContentBeforeCallingCryptoPro(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{Result: domain.ValidResult(sampleSignInfo())}
	server, _ := newAPI(t, verifier)

	req, _ := http.NewRequest(http.MethodPost, server.URL+endpoint, strings.NewReader("type=attached"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest || verifier.Calls != 0 {
		t.Fatalf("status %d calls %d", resp.StatusCode, verifier.Calls)
	}
}

func TestRejectsInvalidRequestsBeforeCallingCryptoPro(t *testing.T) {
	cases := map[string]any{
		"missing signature": map[string]any{"type": "attached", "format": "bes"},
		"unknown type":      map[string]any{"type": "opaque", "format": "bes", "sign": base64.StdEncoding.EncodeToString([]byte(syntheticCMS))},
		"unknown format":    map[string]any{"type": "attached", "format": "cades-a", "sign": base64.StdEncoding.EncodeToString([]byte(syntheticCMS))},
		"unsupported xlong": map[string]any{"type": "attached", "format": "xlongtype1", "sign": base64.StdEncoding.EncodeToString([]byte(syntheticCMS))},
		"invalid base64":    map[string]any{"type": "attached", "format": "bes", "sign": "!!!!"},
		"detached no file":  map[string]any{"type": "detached", "format": "bes", "sign": base64.StdEncoding.EncodeToString([]byte(syntheticCMS))},
		"attached with file": map[string]any{
			"type": "attached", "format": "bes",
			"sign": base64.StdEncoding.EncodeToString([]byte(syntheticCMS)),
			"file": base64.StdEncoding.EncodeToString([]byte(syntheticFile)),
		},
		"attached null file": map[string]any{
			"type": "attached", "format": "bes",
			"sign": base64.StdEncoding.EncodeToString([]byte(syntheticCMS)),
			"file": nil,
		},
		"unexpected field": map[string]any{
			"type": "attached", "format": "bes",
			"sign":       base64.StdEncoding.EncodeToString([]byte(syntheticCMS)),
			"unexpected": true,
		},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			verifier := &testsupport.RecordingVerifier{Result: domain.ValidResult(sampleSignInfo())}
			server, _ := newAPI(t, verifier)
			resp := postJSON(t, server, payload)
			body := readBody(t, resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d body %s", resp.StatusCode, body)
			}
			assertJSONEqual(t, invalidJSON, body)
			if resp.Header.Get("X-Guid") == "" {
				t.Fatal("missing X-Guid")
			}
			if verifier.Calls != 0 {
				t.Fatalf("verifier called %d times", verifier.Calls)
			}
		})
	}
}

func TestMapsProviderFailuresWithoutLeakingProviderOutput(t *testing.T) {
	cases := []struct {
		failure domain.Failure
		status  int
	}{
		{domain.InvalidSignatureStructure, 400},
		{domain.CertificateMetadataError, 502},
		{domain.Disabled, 503},
		{domain.Unavailable, 503},
		{domain.Timeout, 504},
		{domain.Interrupted, 503},
		{domain.ProviderError, 502},
		{domain.OutcomeUnknown, 503},
	}
	for _, tc := range cases {
		t.Run(string(tc.failure), func(t *testing.T) {
			verifier := &testsupport.RecordingVerifier{
				Result: domain.ValidResult(sampleSignInfo()),
				Err:    domain.Fail(tc.failure),
			}
			server, _ := newAPI(t, verifier)
			resp := postJSON(t, server, map[string]any{
				"type":   "attached",
				"format": "bes",
				"sign":   base64.StdEncoding.EncodeToString([]byte(syntheticCMS)),
			})
			body := readBody(t, resp)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d body %s", resp.StatusCode, body)
			}
			if !strings.Contains(body, `"code":`+itoa(tc.status)) {
				t.Fatalf("body %s", body)
			}
			if strings.Contains(body, "sensitive provider output") {
				t.Fatal("leaked provider output")
			}
			if resp.Header.Get("X-Guid") == "" {
				t.Fatal("missing X-Guid")
			}
		})
	}
}

func TestLogsOnlySafeCorrelatedValidationMetadata(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{
		Result: domain.ValidResult(sampleSignInfo()),
		Err:    domain.Fail(domain.ProviderError),
	}
	server, logs := newAPI(t, verifier)
	resp := postJSON(t, server, map[string]any{
		"type":   "attached",
		"format": "bes",
		"sign":   base64.StdEncoding.EncodeToString([]byte(syntheticCMS)),
	})
	_ = readBody(t, resp)
	records := logs.Snapshot()
	if len(records) != 1 {
		t.Fatalf("got %d log records", len(records))
	}
	ctx := records[0].Attrs
	if ctx["x_guid"] != resp.Header.Get("X-Guid") {
		t.Fatalf("guid mismatch %v %s", ctx["x_guid"], resp.Header.Get("X-Guid"))
	}
	if ctx["failure"] != string(domain.ProviderError) || ctx["type"] != "attached" || ctx["format"] != "bes" {
		t.Fatalf("unsafe or incomplete log context: %#v", ctx)
	}
	if _, ok := ctx["duration_ms"].(float64); !ok {
		t.Fatalf("duration_ms %T", ctx["duration_ms"])
	}
	serialized, _ := json.Marshal(records)
	if strings.Contains(string(serialized), "sensitive provider output") ||
		strings.Contains(string(serialized), base64.StdEncoding.EncodeToString([]byte(syntheticCMS))) {
		t.Fatal("log leaked payload bytes")
	}
}

func TestDisabledFlagDoesNotCallVerifier(t *testing.T) {
	verifier := &testsupport.RecordingVerifier{Result: domain.ValidResult(sampleSignInfo())}
	logs := &testsupport.RecordingHandler{}
	handler := httpapi.NewHandler(validate.NewService(verifier, false), slog.New(logs))
	server := httptest.NewServer(httpapi.NewServer("", handler).Handler)
	t.Cleanup(server.Close)

	resp := postJSON(t, server, map[string]any{
		"type":   "attached",
		"format": "bes",
		"sign":   base64.StdEncoding.EncodeToString([]byte(syntheticCMS)),
	})
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if verifier.Calls != 0 {
		t.Fatal("disabled service called the verifier")
	}
	if !strings.Contains(body, "CryptoPro signature verification is disabled.") {
		t.Fatalf("body %s", body)
	}
}

func assertJSONEqual(t *testing.T, expected, actual string) {
	t.Helper()
	var left, right any
	if err := json.Unmarshal([]byte(expected), &left); err != nil {
		t.Fatalf("expected json: %v", err)
	}
	if err := json.Unmarshal([]byte(actual), &right); err != nil {
		t.Fatalf("actual json: %v %s", err, actual)
	}
	leftRaw, _ := json.Marshal(left)
	rightRaw, _ := json.Marshal(right)
	if string(leftRaw) != string(rightRaw) {
		t.Fatalf("json mismatch\nexpected %s\nactual   %s", leftRaw, rightRaw)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
