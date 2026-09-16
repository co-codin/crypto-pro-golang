package validate

import (
	"crypto-pro/internal/domain"
	"encoding/json"
	"strings"
)

// Request is the strict JSON body for POST /api/crypto/v1/validate.
type Request struct {
	Type   domain.SignatureType
	Format string
	Sign   string
	File   *string
}

type rawRequest map[string]json.RawMessage

func ParseRequest(body []byte) (Request, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	var raw rawRequest
	if err := dec.Decode(&raw); err != nil {
		return Request{}, domain.Fail(domain.InvalidSignatureInput)
	}
	if dec.More() {
		return Request{}, domain.Fail(domain.InvalidSignatureInput)
	}

	allowed := map[string]struct{}{"type": {}, "format": {}, "sign": {}, "file": {}}
	for key := range raw {
		if _, ok := allowed[key]; !ok {
			return Request{}, domain.Fail(domain.InvalidSignatureInput)
		}
	}

	typeValue, err := requiredString(raw, "type")
	if err != nil {
		return Request{}, err
	}
	signatureType, ok := domain.ParseSignatureType(typeValue)
	if !ok {
		return Request{}, domain.Fail(domain.InvalidSignatureInput)
	}

	format, err := requiredString(raw, "format")
	if err != nil {
		return Request{}, err
	}
	if format != domain.FormatBES {
		return Request{}, domain.Fail(domain.InvalidSignatureInput)
	}

	sign, err := requiredString(raw, "sign")
	if err != nil {
		return Request{}, err
	}

	file, filePresent, err := optionalString(raw, "file")
	if err != nil {
		return Request{}, err
	}
	if signatureType == domain.TypeAttached && filePresent {
		return Request{}, domain.Fail(domain.InvalidSignatureInput)
	}
	if signatureType == domain.TypeDetached && !filePresent {
		return Request{}, domain.Fail(domain.InvalidSignatureInput)
	}

	req := Request{Type: signatureType, Format: format, Sign: sign}
	if filePresent {
		req.File = file
	}
	return req, nil
}

func requiredString(raw rawRequest, key string) (string, error) {
	value, ok := raw[key]
	if !ok {
		return "", domain.Fail(domain.InvalidSignatureInput)
	}
	var parsed string
	if err := json.Unmarshal(value, &parsed); err != nil {
		return "", domain.Fail(domain.InvalidSignatureInput)
	}
	if strings.TrimSpace(parsed) == "" {
		return "", domain.Fail(domain.InvalidSignatureInput)
	}
	return parsed, nil
}

func optionalString(raw rawRequest, key string) (*string, bool, error) {
	value, ok := raw[key]
	if !ok {
		return nil, false, nil
	}
	if string(value) == "null" {
		empty := ""
		return &empty, true, nil
	}
	var parsed string
	if err := json.Unmarshal(value, &parsed); err != nil {
		return nil, true, domain.Fail(domain.InvalidSignatureInput)
	}
	return &parsed, true, nil
}
