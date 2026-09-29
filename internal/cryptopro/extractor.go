package cryptopro

import (
	"crypto/sha1"
	"encoding/hex"

	"crypto-pro/internal/domain"
)

const (
	pkcs7SignedDataOID      = "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
	maxCertificateBytes     = 1024 * 1024
	maxCertificateBundle    = 2 * 1024 * 1024
	maxEmbeddedCertificates = 16
)

// CMSExtractor pulls embedded signer certificates from a CMS SignedData blob.
type CMSExtractor struct{}

func NewCMSExtractor() CMSExtractor {
	return CMSExtractor{}
}

// Extract returns SHA-1 fingerprint (hex) → canonical DER certificate.
func (CMSExtractor) Extract(cms []byte) (map[string][]byte, error) {
	tag, content, err := readElement(cms, 0, len(cms))
	if err != nil || tag != 0x30 {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}

	offset := 0
	oidTag, oid, err := readElement(content, offset, len(content))
	if err != nil {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}
	offset, err = elementEnd(content, offset)
	if err != nil {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}
	if oidTag != 0x06 || string(oid) != pkcs7SignedDataOID {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}

	explicitTag, explicit, err := readElement(content, offset, len(content))
	if err != nil || explicitTag != 0xa0 {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}

	signedTag, signedData, err := readElement(explicit, 0, len(explicit))
	if err != nil || signedTag != 0x30 {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}

	position := 0
	for i := 0; i < 3; i++ {
		if _, _, err := readElement(signedData, position, len(signedData)); err != nil {
			return nil, domain.Fail(domain.InvalidSignatureStructure)
		}
		position, err = elementEnd(signedData, position)
		if err != nil {
			return nil, domain.Fail(domain.InvalidSignatureStructure)
		}
	}
	if position >= len(signedData) {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}

	certificatesTag, certificatesBlob, err := readElement(signedData, position, len(signedData))
	if err != nil || certificatesTag != 0xa0 {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}

	certificates := map[string][]byte{}
	cursor := 0
	for cursor < len(certificatesBlob) {
		start := cursor
		certTag, _, err := readElement(certificatesBlob, cursor, len(certificatesBlob))
		if err != nil {
			return nil, domain.Fail(domain.InvalidSignatureStructure)
		}
		cursor, err = elementEnd(certificatesBlob, start)
		if err != nil {
			return nil, domain.Fail(domain.InvalidSignatureStructure)
		}
		if certTag != 0x30 {
			return nil, domain.Fail(domain.InvalidSignatureStructure)
		}
		der := certificatesBlob[start:cursor]
		if len(der) == 0 || len(der) > maxCertificateBytes {
			return nil, domain.Fail(domain.InvalidSignatureStructure)
		}
		fingerprint := sha1Hex(der)
		if _, exists := certificates[fingerprint]; exists {
			return nil, domain.Fail(domain.InvalidSignatureStructure)
		}
		certificates[fingerprint] = der
		if len(certificates) > maxEmbeddedCertificates {
			return nil, domain.Fail(domain.InvalidSignatureStructure)
		}
	}
	if len(certificates) == 0 {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}
	return certificates, nil
}

func sha1Hex(der []byte) string {
	sum := sha1.Sum(der)
	return hex.EncodeToString(sum[:])
}
