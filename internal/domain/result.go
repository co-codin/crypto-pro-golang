package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// NameParts is an ordered distinguished-name map. JSON encoding preserves
// insertion order so the wire shape stays stable.
type NameParts struct {
	order  []string
	values map[string]string
}

func NewNameParts() NameParts {
	return NameParts{values: map[string]string{}}
}

func (p *NameParts) Set(key, value string) {
	if key == "" || value == "" {
		return
	}
	if p.values == nil {
		p.values = map[string]string{}
	}
	if _, exists := p.values[key]; !exists {
		p.order = append(p.order, key)
	}
	p.values[key] = value
}

func (p NameParts) Get(key string) (string, bool) {
	if p.values == nil {
		return "", false
	}
	value, ok := p.values[key]
	return value, ok
}

func (p NameParts) Empty() bool {
	return len(p.order) == 0
}

func (p NameParts) Map() map[string]string {
	out := make(map[string]string, len(p.order))
	for _, key := range p.order {
		out[key] = p.values[key]
	}
	return out
}

func (p NameParts) String() string {
	items := make([]string, 0, len(p.order))
	for _, key := range p.order {
		items = append(items, key+"="+escapeDNValue(p.values[key]))
	}
	out := ""
	for i, item := range items {
		if i > 0 {
			out += ", "
		}
		out += item
	}
	return out
}

func (p NameParts) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range p.order {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		valueJSON, err := json.Marshal(p.values[key])
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(valueJSON)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (p *NameParts) UnmarshalJSON(data []byte) error {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*p = NewNameParts()
	for key, value := range raw {
		p.Set(key, value)
	}
	return nil
}

func escapeDNValue(value string) string {
	escaped := make([]byte, 0, len(value)+8)
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\':
			escaped = append(escaped, '\\', '\\')
		case ',':
			escaped = append(escaped, '\\', ',')
		default:
			escaped = append(escaped, value[i])
		}
	}
	return string(escaped)
}

// CertificateInfo is the OpenAPI CertificateInfo object.
type CertificateInfo struct {
	Issuer       string    `json:"issuer"`
	IssuerParts  NameParts `json:"issuerParts"`
	Subject      string    `json:"subject"`
	SubjectParts NameParts `json:"subjectParts"`
	Serial       string    `json:"serial"`
	HexSerial    string    `json:"hexSerial"`
	SHA1         string    `json:"sha1"`
	ValidFrom    string    `json:"validFrom"`
	ValidTo      string    `json:"validTo"`
	SubjectKeyID string    `json:"subjectKeyId"`
}

// Result is the typed outcome of a completed verification.
type Result struct {
	Valid    bool
	SignInfo *CertificateInfo
}

func ValidResult(info CertificateInfo) Result {
	return Result{Valid: true, SignInfo: &info}
}

func InvalidResult() Result {
	return Result{Valid: false}
}

func (r Result) Validate() error {
	if r.Valid != (r.SignInfo != nil) {
		return fmt.Errorf("certificate info must be present only for a valid signature")
	}
	return nil
}

// SignatureType is attached or detached CMS.
type SignatureType string

const (
	TypeAttached SignatureType = "attached"
	TypeDetached SignatureType = "detached"
)

func ParseSignatureType(value string) (SignatureType, bool) {
	switch SignatureType(value) {
	case TypeAttached, TypeDetached:
		return SignatureType(value), true
	default:
		return "", false
	}
}

const FormatBES = "bes"

// Verifier is the CryptoPro provider boundary.
type Verifier interface {
	Verify(signatureType SignatureType, signature []byte, content []byte) (Result, error)
}
