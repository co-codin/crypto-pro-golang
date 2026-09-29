package cryptopro

import (
	"crypto-pro/internal/domain"
	"crypto/x509"
	"encoding/base64"
	"os"
	"regexp"
	"strings"
)

var (
	whitespaceRE = regexp.MustCompile(`\s+`)
	pemRE        = regexp.MustCompile(`(?s)\A-----BEGIN (PKCS7|CERTIFICATE)-----\s*([a-zA-Z0-9+/= \r\n]+?)\s*-----END (?:PKCS7|CERTIFICATE)-----\z`)
	certPEMRE    = regexp.MustCompile(`(?s)\A\s*-----BEGIN CERTIFICATE-----\s*([a-zA-Z0-9+/= \r\n]+?)\s*-----END CERTIFICATE-----\s*\z`)
)

func certificatesFromBundle(path string) (map[string][]byte, error) {
	bundle, err := readPrivateFile(path, maxCertificateBundle)
	if err != nil {
		return nil, err
	}
	pems, err := certificatePEMsFromExport(bundle)
	if err != nil {
		return nil, err
	}

	certificates := map[string][]byte{}
	for _, pem := range pems {
		der, err := certificateDER(pem)
		if err != nil {
			return nil, err
		}
		fingerprint := sha1Hex(der)
		if existing, ok := certificates[fingerprint]; ok {
			if string(existing) == string(der) {
				return nil, domain.Fail(domain.InvalidSignatureStructure)
			}
			return nil, domain.Fail(domain.OutcomeUnknown)
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

func certificatePEMsFromExport(bundle []byte) ([]string, error) {
	der, err := exportedDER(bundle)
	if err != nil {
		return nil, err
	}
	certPEM := pemCertificate(der)
	if _, parseErr := x509.ParseCertificate(der); parseErr == nil {
		return []string{certPEM}, nil
	}

	pkcs7PEM := "-----BEGIN PKCS7-----\n" + wrapBase64(base64.StdEncoding.EncodeToString(der)) + "-----END PKCS7-----\n"
	certs, err := parsePKCS7Certificates(pkcs7PEM, der)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

func parsePKCS7Certificates(pkcs7PEM string, der []byte) ([]string, error) {
	// Prefer walking a CMS/PKCS#7 blob the same way as CMSExtractor.
	if extracted, err := (CMSExtractor{}).Extract(der); err == nil {
		pems := make([]string, 0, len(extracted))
		for _, certDER := range extracted {
			pems = append(pems, pemCertificate(certDER))
		}
		if len(pems) > 0 {
			return pems, nil
		}
	}
	_ = pkcs7PEM
	return nil, domain.Fail(domain.InvalidSignatureStructure)
}

func exportedDER(bundle []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(bundle))
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		matches := pemRE.FindStringSubmatch(trimmed)
		if len(matches) < 3 {
			return nil, domain.Fail(domain.InvalidSignatureStructure)
		}
		trimmed = matches[2]
	}
	canonical := whitespaceRE.ReplaceAllString(trimmed, "")
	der, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil || len(der) == 0 || len(der) > maxCertificateBundle || base64.StdEncoding.EncodeToString(der) != canonical {
		return nil, domain.Fail(domain.CertificateMetadataError)
	}
	return der, nil
}

func certificateDER(pem string) ([]byte, error) {
	matches := certPEMRE.FindStringSubmatch(pem)
	if len(matches) < 2 {
		return nil, domain.Fail(domain.InvalidSignatureStructure)
	}
	body := whitespaceRE.ReplaceAllString(matches[1], "")
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(der) == 0 || len(der) > maxCertificateBytes {
		return nil, domain.Fail(domain.CertificateMetadataError)
	}
	if _, parseErr := x509.ParseCertificate(der); parseErr != nil {
		return nil, domain.Fail(domain.CertificateMetadataError)
	}
	return der, nil
}

func wrapBase64(encoded string) string {
	var b strings.Builder
	for len(encoded) > 0 {
		n := 64
		if n > len(encoded) {
			n = len(encoded)
		}
		b.WriteString(encoded[:n])
		b.WriteByte('\n')
		encoded = encoded[n:]
	}
	return b.String()
}

func readPrivateFile(path string, maxBytes int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, domain.Fail(domain.OutcomeUnknown)
	}
	if info.Size() == 0 || info.Size() > int64(maxBytes) {
		return nil, domain.Fail(domain.OutcomeUnknown)
	}
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 || len(contents) > maxBytes {
		return nil, domain.Fail(domain.OutcomeUnknown)
	}
	return contents, nil
}

func writePrivateFile(path string, contents []byte) error {
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		_ = os.Remove(path)
		return domain.Fail(domain.Unavailable)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		return domain.Fail(domain.Unavailable)
	}
	return nil
}

func createPrivateDirectory() (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		path, err := os.MkdirTemp("", "cryptopro-signature-")
		if err != nil {
			continue
		}
		if err := os.Chmod(path, 0o700); err != nil {
			_ = os.RemoveAll(path)
			continue
		}
		return path, nil
	}
	return "", domain.Fail(domain.Unavailable)
}
