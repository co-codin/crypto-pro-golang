package validate

import (
	"crypto-pro/internal/domain"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

const (
	MaxContentBytes   = 10 * 1024 * 1024
	MaxSignatureBytes = 12 * 1024 * 1024
	MaxRequestBytes   = 32 * 1024 * 1024
)

var whitespaceRE = regexp.MustCompile(`\s+`)

// Service is the application use-case for POST /validate.
type Service struct {
	verifier domain.Verifier
	enabled  bool
}

func NewService(verifier domain.Verifier, enabled bool) *Service {
	return &Service{verifier: verifier, enabled: enabled}
}

func (s *Service) Execute(signatureType domain.SignatureType, encodedSignature string, encodedContent *string) (domain.Result, error) {
	if !s.enabled {
		return domain.Result{}, domain.Fail(domain.Disabled)
	}
	if (signatureType == domain.TypeAttached && encodedContent != nil) ||
		(signatureType == domain.TypeDetached && encodedContent == nil) {
		return domain.Result{}, domain.Fail(domain.InvalidSignatureInput)
	}

	signature, err := decodeBase64(encodedSignature, MaxSignatureBytes, false)
	if err != nil {
		return domain.Result{}, err
	}
	var content []byte
	if encodedContent != nil {
		content, err = decodeBase64(*encodedContent, MaxContentBytes, true)
		if err != nil {
			return domain.Result{}, err
		}
	}
	return s.verifier.Verify(signatureType, signature, content)
}

func decodeBase64(encoded string, maxBytes int, allowEmpty bool) ([]byte, error) {
	canonical := whitespaceRE.ReplaceAllString(encoded, "")
	maxEncodedBytes := 4 * ((maxBytes + 2) / 3)
	if len(canonical) > maxEncodedBytes || (!allowEmpty && canonical == "") {
		return nil, domain.Fail(domain.InvalidSignatureInput)
	}
	decoded, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil || len(decoded) > maxBytes || (!allowEmpty && len(decoded) == 0) {
		return nil, domain.Fail(domain.InvalidSignatureInput)
	}
	reencoded := base64.StdEncoding.EncodeToString(decoded)
	if subtle.ConstantTimeCompare([]byte(reencoded), []byte(canonical)) != 1 {
		return nil, domain.Fail(domain.InvalidSignatureInput)
	}
	return decoded, nil
}
