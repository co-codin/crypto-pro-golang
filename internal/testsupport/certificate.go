package testsupport

import (
	"encoding/base64"
	"regexp"
	"strings"
)

const leafPEM = `-----BEGIN CERTIFICATE-----
MIIDjTCCAnWgAwIBAgIUastF3RvqbyzbrxukuCguVfr/tvUwDQYJKoZIhvcNAQEL
BQAwRTElMCMGA1UEAwwcY3J5cHRvLXByby1sZWFmLXRlc3QuaW52YWxpZDEcMBoG
A1UECgwTU3ludGhldGljIFRlc3QgT25seTAeFw0yNjA3MTYwODU2MzlaFw0zNjA3
MTMwODU2MzlaMEUxJTAjBgNVBAMMHGNyeXB0by1wcm8tbGVhZi10ZXN0LmludmFs
aWQxHDAaBgNVBAoME1N5bnRoZXRpYyBUZXN0IE9ubHkwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDxUh7vXbsKWFLjW+3ga1qkVPu2sspr8u4NigM/UhDt
YVKj0QyWe3+/4NoYMbCHK40o9zDoey04kUS+Lmf/BXLuCafCr6anHjXgoChAbAwl
dINxagy8/X+50jm3YM8UJUrBPfpcmPVHxQPyo268JTB2HobCxQKoIHQiBB1WAnxN
MaLBK0OWkYK7Isv+wZHF/4uPal3VbuZoaG6Wla7OBRZph8w7k+LTI2rsqICaAIam
32kdvvemCnIICtmcXK3A0/hQ4RpzF0IYykQjBDDdA+Tr3Sx/ezGYOZsCHBcBpb2e
mb9s5h75vyk7tQnZxcYLiHi2Rqaq9JmVaHnRJu1UjX6fAgMBAAGjdTBzMB0GA1Ud
DgQWBBRWlUMikhwY5NMNtvY0UPx4OEvI6DAfBgNVHSMEGDAWgBRWlUMikhwY5NMN
tvY0UPx4OEvI6DAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQsFAAOCAQEASlpkuNQCTPV9+QQgN+iu
RvjE0jC0qAu7vGAinWXOQi05UjqYcPn53/FTNqxOj+5Wm3H2DDT5/TGB8xCPMoOQ
IMt0H8TKCHGNV3tFD5qDea9EpS6mssTQLVi4rDU2zt4fThZYFH+w01YNmOSkvBTi
N2f6aw6HIWetJTmbHGBULDF8Qy5X3w2TABtYMBQTW65dVsXw3Sg6jTl5vRkn46zZ
pBNfMgpV/BM6fiXRg2HYE2BJqJbKp+0scETDjR72qCGP5Qql9nZPCkLf/x2wkOJy
s0penFdSWti9wP5MQ1OzxtQDEnVG6rwBbzMJBwvEIhg44+hFqzuWMbP9R7UyVbXe
XA==
-----END CERTIFICATE-----`

const innlePEM = `-----BEGIN CERTIFICATE-----
MIIELjCCAxagAwIBAgIUUHGtDcnJJy6IwmOszxx1a948DBswDQYJKoZIhvcNAQEL
BQAwgagxIzAhBgNVBAMMGmNyeXB0by1wcm8taW5ubGUtbGVhZi50ZXN0MRwwGgYD
VQQKDBNTeW50aGV0aWMgVGVzdCBPbmx5MRUwEwYFKoUDZAQMCjEyMzQ1Njc4OTAx
GjAYBggqhQMDgQMBARIMMTIzNDU2Nzg5MDEyMRYwFAYFKoUDZAMSCzEyMzQ1Njc4
OTAxMRgwFgYFKoUDZAESDTEyMzQ1Njc4OTAxMjMwHhcNMjYwOTEwMTExNzMyWhcN
MzYwOTA3MTExNzMyWjCBqDEjMCEGA1UEAwwaY3J5cHRvLXByby1pbm5sZS1sZWFm
LnRlc3QxHDAaBgNVBAoME1N5bnRoZXRpYyBUZXN0IE9ubHkxFTATBgUqhQNkBAwK
MTIzNDU2Nzg5MDEaMBgGCCqFAwOBAwEBEgwxMjM0NTY3ODkwMTIxFjAUBgUqhQNk
AxILMTIzNDU2Nzg5MDExGDAWBgUqhQNkARINMTIzNDU2Nzg5MDEyMzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANFGcoVJRZXPsEMtj0SLAw02w1NvkUiB
Ycq0i6JoasVQKlDrKeZ7BIB35JRzMdWSHkbCVqdTkFXlyTgKvyO0/BxNShSYU4XZ
hNd6jk85bEq14YJvfRrqe0FCjaMQZxlhrkFrvcC9vM5TBC+PwYR3VLk0UjCx6vDv
Q0K05GZnmp4YA2EXd11NSIsokaa6r78RA78oRwxHUPbzwvMW2LzV+3Thmqs5AwAw
av9FtmSjv/YVs8ZnY0l85AkaQKvK3TSNL57yQJF110+nX948ltJl0j70bi+7fwrx
MI2vEJCGpvAIkQa0ciIC1ZEdHpDx3v45odzspP4szxCWSKoxBw7tl9UCAwEAAaNO
MEwwCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIw
HQYDVR0OBBYEFB+++2/FJKSSuzyXqu68G61Ee3RMMA0GCSqGSIb3DQEBCwUAA4IB
AQAUyhsFBeNERklRMorxEZ6FdwajOFa6wKzJd9nDRvot+NoZbiQ+u03HukWy/c1r
O9OGWWMkoegWjE9hDAXefIPvvIAwwPfBk2WB18XE1QxvyPVpoEIXSzXUPZ/heKpJ
Wy1N15tmcXlfLoT+jEPL3rm5AValC1eCHpc2e/kqI4DHLv41QHVNNXenIMXmQk5l
Lydhtj5pMxl1t0gjXA/SpB/ItsZezY/XjZZ7aPtF3aUoEh+MwZaS2NHzgXiQHte6
BL6B+9vSfxy6uyiHpEYw7W0s6oEgCePx9owBqObeMJspw6g5HpO8IRW5aQoiET8J
B0QAaEo+ug2FH9FKSsorOKwh
-----END CERTIFICATE-----`

var pemBodyRE = regexp.MustCompile(`-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+`)

func LeafDER() []byte {
	return pemToDER(leafPEM)
}

func InnleDER() []byte {
	return pemToDER(innlePEM)
}

func pemToDER(pem string) []byte {
	body := pemBodyRE.ReplaceAllString(pem, "")
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		panic("testsupport: invalid test certificate")
	}
	return der
}

func WrapBase64(raw []byte, width int, sep string) string {
	encoded := base64.StdEncoding.EncodeToString(raw)
	if width <= 0 {
		return encoded
	}
	var b strings.Builder
	for len(encoded) > 0 {
		n := width
		if n > len(encoded) {
			n = len(encoded)
		}
		b.WriteString(encoded[:n])
		b.WriteString(sep)
		encoded = encoded[n:]
	}
	return b.String()
}
