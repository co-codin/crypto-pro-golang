package cryptopro

import (
	"crypto-pro/internal/domain"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"time"
	"unicode/utf16"
)

var (
	oidCN     = []byte{0x55, 0x04, 0x03}
	oidSN     = []byte{0x55, 0x04, 0x04}
	oidC      = []byte{0x55, 0x04, 0x06}
	oidL      = []byte{0x55, 0x04, 0x07}
	oidS      = []byte{0x55, 0x04, 0x08}
	oidStreet = []byte{0x55, 0x04, 0x09}
	oidO      = []byte{0x55, 0x04, 0x0a}
	oidOU     = []byte{0x55, 0x04, 0x0b}
	oidT      = []byte{0x55, 0x04, 0x0c}
	oidG      = []byte{0x55, 0x04, 0x2a}
	oidE      = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01}
	oidINN    = []byte{0x2a, 0x85, 0x03, 0x03, 0x81, 0x03, 0x01, 0x01}
	oidINNLE  = []byte{0x2a, 0x85, 0x03, 0x64, 0x04}
	oidOGRN   = []byte{0x2a, 0x85, 0x03, 0x64, 0x01}
	oidSNILS  = []byte{0x2a, 0x85, 0x03, 0x64, 0x03}
	oidOGRNIP = []byte{0x2a, 0x85, 0x03, 0x64, 0x05}
	oidSKI    = []byte{0x55, 0x1d, 0x0e}
)

var nameOIDKeys = []struct {
	oid []byte
	key string
}{
	{oidC, "C"},
	{oidS, "S"},
	{oidL, "L"},
	{oidStreet, "STREET"},
	{oidO, "O"},
	{oidOU, "OU"},
	{oidCN, "CN"},
	{oidT, "T"},
	{oidE, "E"},
	{oidG, "G"},
	{oidSN, "SN"},
	{oidINN, "INN"},
	{oidINNLE, "INNLE"},
	{oidOGRN, "OGRN"},
	{oidOGRNIP, "OGRNIP"},
	{oidSNILS, "SNILS"},
}

func certificateInfo(der []byte) (domain.CertificateInfo, error) {
	issuer, subject, serial, hexSerial, validFrom, validTo, ski, err := parseTBSCertificate(der)
	if err != nil {
		return domain.CertificateInfo{}, err
	}
	if issuer.Empty() || subject.Empty() || hexSerial == "" || serial == "" {
		return domain.CertificateInfo{}, domain.Fail(domain.CertificateMetadataError)
	}
	return domain.CertificateInfo{
		Issuer:       issuer.String(),
		IssuerParts:  issuer,
		Subject:      subject.String(),
		SubjectParts: subject,
		Serial:       serial,
		HexSerial:    hexSerial,
		SHA1:         sha1Hex(der),
		ValidFrom:    validFrom,
		ValidTo:      validTo,
		SubjectKeyID: ski,
	}, nil
}

func parseTBSCertificate(der []byte) (issuer, subject domain.NameParts, serial, hexSerial, validFrom, validTo, ski string, err error) {
	tag, outer, err := readElementAs(der, 0, len(der), domain.CertificateMetadataError)
	if err != nil || tag != 0x30 {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", domain.Fail(domain.CertificateMetadataError)
	}
	tbsTag, tbs, err := readElementAs(outer, 0, len(outer), domain.CertificateMetadataError)
	if err != nil || tbsTag != 0x30 {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", domain.Fail(domain.CertificateMetadataError)
	}

	offset := 0
	end := len(tbs)
	firstTag, _, err := readElementAs(tbs, offset, end, domain.CertificateMetadataError)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}
	if firstTag == 0xa0 {
		offset, err = elementEndAs(tbs, offset, domain.CertificateMetadataError)
		if err != nil {
			return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
		}
	}

	serialTag, serialBytes, err := readElementAs(tbs, offset, end, domain.CertificateMetadataError)
	if err != nil || serialTag != 0x02 {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", domain.Fail(domain.CertificateMetadataError)
	}
	serial, hexSerial, err = formatSerial(serialBytes)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}
	offset, err = elementEndAs(tbs, offset, domain.CertificateMetadataError)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}

	if _, _, err = readElementAs(tbs, offset, end, domain.CertificateMetadataError); err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}
	offset, err = elementEndAs(tbs, offset, domain.CertificateMetadataError)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}

	issuerTag, issuerDER, err := readElementAs(tbs, offset, end, domain.CertificateMetadataError)
	if err != nil || issuerTag != 0x30 {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", domain.Fail(domain.CertificateMetadataError)
	}
	issuer, err = nameOIDParts(issuerDER)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}
	offset, err = elementEndAs(tbs, offset, domain.CertificateMetadataError)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}

	validityTag, validity, err := readElementAs(tbs, offset, end, domain.CertificateMetadataError)
	if err != nil || validityTag != 0x30 {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", domain.Fail(domain.CertificateMetadataError)
	}
	validFrom, validTo, err = parseValidity(validity)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}
	offset, err = elementEndAs(tbs, offset, domain.CertificateMetadataError)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}

	subjectTag, subjectDER, err := readElementAs(tbs, offset, end, domain.CertificateMetadataError)
	if err != nil || subjectTag != 0x30 {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", domain.Fail(domain.CertificateMetadataError)
	}
	subject, err = nameOIDParts(subjectDER)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}
	offset, err = elementEndAs(tbs, offset, domain.CertificateMetadataError)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}

	if _, _, err = readElementAs(tbs, offset, end, domain.CertificateMetadataError); err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}
	offset, err = elementEndAs(tbs, offset, domain.CertificateMetadataError)
	if err != nil {
		return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
	}

	for offset < end {
		tag, value, readErr := readElementAs(tbs, offset, end, domain.CertificateMetadataError)
		if readErr != nil {
			break
		}
		if tag == 0xa3 {
			ski = subjectKeyID(value)
			break
		}
		offset, err = elementEndAs(tbs, offset, domain.CertificateMetadataError)
		if err != nil {
			return domain.NameParts{}, domain.NameParts{}, "", "", "", "", "", err
		}
	}
	return issuer, subject, serial, hexSerial, validFrom, validTo, ski, nil
}

func formatSerial(raw []byte) (string, string, error) {
	if len(raw) == 0 {
		return "", "", domain.Fail(domain.CertificateMetadataError)
	}
	hexSerial := strings.ToUpper(hex.EncodeToString(raw))
	if hexSerial == "" {
		return "", "", domain.Fail(domain.CertificateMetadataError)
	}
	n := new(big.Int).SetBytes(raw)
	return n.String(), hexSerial, nil
}

func parseValidity(validity []byte) (string, string, error) {
	offset := 0
	fromTag, fromRaw, err := readElementAs(validity, offset, len(validity), domain.CertificateMetadataError)
	if err != nil {
		return "", "", err
	}
	offset, err = elementEndAs(validity, offset, domain.CertificateMetadataError)
	if err != nil {
		return "", "", err
	}
	toTag, toRaw, err := readElementAs(validity, offset, len(validity), domain.CertificateMetadataError)
	if err != nil {
		return "", "", err
	}
	from, err := parseASN1Time(fromTag, fromRaw)
	if err != nil {
		return "", "", err
	}
	to, err := parseASN1Time(toTag, toRaw)
	if err != nil {
		return "", "", err
	}
	return formatAtom(from), formatAtom(to), nil
}

func parseASN1Time(tag byte, raw []byte) (time.Time, error) {
	text := string(raw)
	var parsed time.Time
	var err error
	switch tag {
	case 0x17:
		parsed, err = time.Parse("060102150405Z", text)
		if err != nil {
			parsed, err = time.Parse("0601021504Z", text)
		}
	case 0x18:
		parsed, err = time.Parse("20060102150405Z", text)
		if err != nil {
			parsed, err = time.Parse("200601021504Z", text)
		}
	default:
		return time.Time{}, domain.Fail(domain.CertificateMetadataError)
	}
	if err != nil {
		return time.Time{}, domain.Fail(domain.CertificateMetadataError)
	}
	return parsed.UTC(), nil
}

func formatAtom(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05+00:00")
}

func nameOIDParts(nameDER []byte) (domain.NameParts, error) {
	parts := domain.NewNameParts()
	offset := 0
	end := len(nameDER)
	for offset < end {
		rdnTag, rdn, err := readElementAs(nameDER, offset, end, domain.CertificateMetadataError)
		if err != nil {
			return domain.NameParts{}, err
		}
		offset, err = elementEndAs(nameDER, offset, domain.CertificateMetadataError)
		if err != nil {
			return domain.NameParts{}, err
		}
		if rdnTag != 0x31 {
			continue
		}
		rdnOffset := 0
		for rdnOffset < len(rdn) {
			attrTag, attr, err := readElementAs(rdn, rdnOffset, len(rdn), domain.CertificateMetadataError)
			if err != nil {
				return domain.NameParts{}, err
			}
			rdnOffset, err = elementEndAs(rdn, rdnOffset, domain.CertificateMetadataError)
			if err != nil {
				return domain.NameParts{}, err
			}
			if attrTag != 0x30 {
				continue
			}
			attrOffset := 0
			oidTag, oid, err := readElementAs(attr, attrOffset, len(attr), domain.CertificateMetadataError)
			if err != nil || oidTag != 0x06 {
				continue
			}
			key, ok := lookupNameOID(oid)
			if !ok {
				continue
			}
			attrOffset, err = elementEndAs(attr, attrOffset, domain.CertificateMetadataError)
			if err != nil {
				return domain.NameParts{}, err
			}
			value := directoryString(attr, attrOffset)
			if value != "" {
				parts.Set(key, value)
			}
		}
	}
	return parts, nil
}

func lookupNameOID(oid []byte) (string, bool) {
	for _, item := range nameOIDKeys {
		if string(item.oid) == string(oid) {
			return item.key, true
		}
	}
	return "", false
}

func directoryString(data []byte, offset int) string {
	tag, value, err := readElement(data, offset, len(data))
	if err != nil {
		return ""
	}
	if tag == 0x31 {
		if len(value) == 0 {
			return ""
		}
		return directoryString(value, 0)
	}
	switch tag {
	case 0x0c, 0x12, 0x13, 0x16, 0x1a:
		return string(value)
	case 0x1e:
		if len(value)%2 != 0 {
			return ""
		}
		u16 := make([]uint16, len(value)/2)
		for i := 0; i < len(u16); i++ {
			u16[i] = uint16(value[i*2])<<8 | uint16(value[i*2+1])
		}
		return string(utf16.Decode(u16))
	default:
		return ""
	}
}

func subjectKeyID(extensionsExplicit []byte) string {
	tag, extensions, err := readElement(extensionsExplicit, 0, len(extensionsExplicit))
	if err != nil || tag != 0x30 {
		return ""
	}
	offset := 0
	for offset < len(extensions) {
		extTag, ext, err := readElement(extensions, offset, len(extensions))
		if err != nil || extTag != 0x30 {
			return ""
		}
		next, err := elementEnd(extensions, offset)
		if err != nil {
			return ""
		}
		offset = next
		extOffset := 0
		oidTag, oid, err := readElement(ext, extOffset, len(ext))
		if err != nil || oidTag != 0x06 {
			continue
		}
		extOffset, err = elementEnd(ext, extOffset)
		if err != nil {
			return ""
		}
		if string(oid) != string(oidSKI) {
			continue
		}
		nextTag, nextValue, err := readElement(ext, extOffset, len(ext))
		if err != nil {
			return ""
		}
		if nextTag == 0x01 { // critical BOOLEAN
			extOffset, err = elementEnd(ext, extOffset)
			if err != nil {
				return ""
			}
			nextTag, nextValue, err = readElement(ext, extOffset, len(ext))
			if err != nil {
				return ""
			}
		}
		if nextTag != 0x04 {
			return ""
		}
		innerTag, inner, err := readElement(nextValue, 0, len(nextValue))
		if err == nil && innerTag == 0x04 {
			return strings.ToLower(hex.EncodeToString(inner))
		}
		return strings.ToLower(hex.EncodeToString(nextValue))
	}
	return ""
}

func pemCertificate(der []byte) string {
	encoded := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(encoded) > 0 {
		n := 64
		if n > len(encoded) {
			n = len(encoded)
		}
		b.WriteString(encoded[:n])
		b.WriteByte('\n')
		encoded = encoded[n:]
	}
	b.WriteString("-----END CERTIFICATE-----\n")
	return b.String()
}
