package domain

// Failure is the closed set of expected CryptoPro outcomes, matching the
// Symfony CryptoProFailure taxonomy.
type Failure string

const (
	InvalidSignatureInput     Failure = "invalid_signature_input"
	InvalidSignatureStructure Failure = "invalid_signature_structure"
	CertificateMetadataError  Failure = "certificate_metadata_error"
	Disabled                  Failure = "disabled"
	Unavailable               Failure = "unavailable"
	Timeout                   Failure = "timeout"
	Interrupted               Failure = "interrupted"
	ProviderError             Failure = "provider_error"
	OutcomeUnknown            Failure = "outcome_unknown"
)

func (f Failure) Error() string {
	return string(f)
}

// Error is a typed, expected verification failure. It never carries provider
// stdout/stderr, CMS bytes, certificate material, or filesystem paths.
type Error struct {
	Failure Failure
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Failure)
}

func Fail(failure Failure) *Error {
	return &Error{Failure: failure}
}

func AsError(err error) (*Error, bool) {
	if err == nil {
		return nil, false
	}
	typed, ok := err.(*Error)
	return typed, ok
}
