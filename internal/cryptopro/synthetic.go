package cryptopro

import "crypto-pro/internal/domain"

// SyntheticVerifier extracts the embedded CMS certificate and treats the
// signature as valid. It is the licensed-CSP-free development stand-in.
type SyntheticVerifier struct {
	extractor CMSExtractor
}

func NewSyntheticVerifier() *SyntheticVerifier {
	return &SyntheticVerifier{extractor: NewCMSExtractor()}
}

func (v *SyntheticVerifier) Verify(signatureType domain.SignatureType, signature []byte, content []byte) (domain.Result, error) {
	_ = signatureType
	_ = content
	certificates, err := v.extractor.Extract(signature)
	if err != nil {
		return domain.Result{}, err
	}
	if len(certificates) != 1 {
		return domain.Result{}, domain.Fail(domain.InvalidSignatureStructure)
	}
	var der []byte
	for _, certificate := range certificates {
		der = certificate
	}
	info, err := certificateInfo(der)
	if err != nil {
		return domain.Result{}, err
	}
	return domain.ValidResult(info), nil
}
