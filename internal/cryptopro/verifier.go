package cryptopro

import (
	"crypto-pro/internal/domain"
	"crypto/subtle"
	"os"
	"path/filepath"
	"time"
)

const (
	successErrorCode          = "00000000"
	invalidSignatureErrorCode = "200001f9"
	notSignerErrorCode        = "200001fb"
	revocationOfflineCode     = "20000133"
)

// Options configure the CryptoPro cryptcp driver.
type Options struct {
	CryptcpPath        string
	Timeout            time.Duration
	Deadline           time.Duration
	AllowStaleCRL      bool
	MaxContentBytes    int
	CertificateExtract CMSExtractor
}

// Verifier runs cryptcp against a private per-request temp directory.
type Verifier struct {
	cryptcpPath     string
	timeout         time.Duration
	deadline        time.Duration
	allowStaleCRL   bool
	maxContentBytes int
	extractor       CMSExtractor
}

func NewVerifier(opts Options) *Verifier {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := opts.Deadline
	if deadline <= 0 {
		deadline = 45 * time.Second
	}
	maxContent := opts.MaxContentBytes
	if maxContent <= 0 {
		maxContent = 10 * 1024 * 1024
	}
	return &Verifier{
		cryptcpPath:     opts.CryptcpPath,
		timeout:         timeout,
		deadline:        deadline,
		allowStaleCRL:   opts.AllowStaleCRL,
		maxContentBytes: maxContent,
		extractor:       opts.CertificateExtract,
	}
}

func (v *Verifier) Verify(signatureType domain.SignatureType, signature []byte, content []byte) (domain.Result, error) {
	deadline := time.Now().Add(v.deadline)
	directory, err := createPrivateDirectory()
	if err != nil {
		return domain.Result{}, err
	}
	contentPath := filepath.Join(directory, "content.bin")
	signaturePath := filepath.Join(directory, "signature.sgn")
	if signatureType == domain.TypeDetached {
		signaturePath = filepath.Join(directory, "content.bin.sgn")
	}
	certificateBundlePath := filepath.Join(directory, "certificates.p7b")
	signerCertificatePath := filepath.Join(directory, "signer.cer")
	var certificatePaths []string

	defer func() {
		for _, path := range append(certificatePaths, signerCertificatePath, certificateBundlePath, contentPath, signaturePath) {
			_ = os.Remove(path)
		}
		_ = os.Remove(directory)
	}()

	if err := writePrivateFile(signaturePath, signature); err != nil {
		return domain.Result{}, err
	}
	if content != nil {
		if err := writePrivateFile(contentPath, content); err != nil {
			return domain.Result{}, err
		}
	}

	certificates, err := v.certificatesFromSignature(signature, signaturePath, certificateBundlePath, deadline)
	if err != nil {
		return domain.Result{}, err
	}
	for fingerprint, certificate := range certificates {
		path := filepath.Join(directory, "cert-"+fingerprint+".cer")
		if err := writePrivateFile(path, certificate); err != nil {
			return domain.Result{}, err
		}
		certificatePaths = append(certificatePaths, path)
	}

	signer, err := v.findSigner(signatureType, signaturePath, contentPath, directory, certificates, deadline)
	if err != nil {
		return domain.Result{}, err
	}
	if !signer.valid {
		return domain.InvalidResult(), nil
	}

	exported := signer.certificate
	if subtle.ConstantTimeCompare([]byte(signer.fingerprint), []byte(sha1Hex(exported))) != 1 {
		return domain.Result{}, domain.Fail(domain.OutcomeUnknown)
	}

	if signatureType == domain.TypeAttached {
		_ = os.Remove(contentPath)
	}
	certificatePath := filepath.Join(directory, "cert-"+signer.fingerprint+".cer")
	finalResult, err := v.run(v.finalVerificationArguments(signatureType, signaturePath, contentPath, certificatePath, signer.fingerprint), deadline)
	if err != nil {
		return domain.Result{}, err
	}
	if v.allowStaleCRL && isRevocationOffline(finalResult) {
		finalResult, err = v.run(v.fallbackVerificationArguments(signatureType, signaturePath, contentPath, certificatePath, signer.fingerprint), deadline)
		if err != nil {
			return domain.Result{}, err
		}
	}
	ok, err := classifyFinalVerification(finalResult)
	if err != nil {
		return domain.Result{}, err
	}
	if !ok {
		return domain.InvalidResult(), nil
	}
	if signatureType == domain.TypeAttached {
		if err := v.assertAttachedContent(contentPath); err != nil {
			return domain.Result{}, err
		}
	}
	info, err := certificateInfo(exported)
	if err != nil {
		return domain.Result{}, err
	}
	return domain.ValidResult(info), nil
}

type signerCandidate struct {
	fingerprint string
	certificate []byte
	valid       bool
}

func (v *Verifier) findSigner(
	signatureType domain.SignatureType,
	signaturePath, contentPath, directory string,
	certificates map[string][]byte,
	deadline time.Time,
) (signerCandidate, error) {
	var signers []signerCandidate
	for fingerprint, certificate := range certificates {
		if signatureType == domain.TypeAttached {
			_ = os.Remove(contentPath)
		}
		result, err := v.run(v.probeArguments(signatureType, signaturePath, contentPath, filepath.Join(directory, "cert-"+fingerprint+".cer"), fingerprint), deadline)
		if err != nil {
			return signerCandidate{}, err
		}
		candidate, skip, err := classifySignerProbe(result)
		if err != nil {
			return signerCandidate{}, err
		}
		if skip {
			continue
		}
		if signatureType == domain.TypeAttached && candidate {
			if err := v.assertAttachedContent(contentPath); err != nil {
				return signerCandidate{}, err
			}
		}
		signers = append(signers, signerCandidate{
			fingerprint: fingerprint,
			certificate: certificate,
			valid:       candidate,
		})
	}
	if len(signers) != 1 {
		return signerCandidate{}, domain.Fail(domain.InvalidSignatureStructure)
	}
	return signers[0], nil
}

func (v *Verifier) probeArguments(signatureType domain.SignatureType, signaturePath, contentPath, certificatePath, fingerprint string) []string {
	return verificationArguments(signatureType, signaturePath, contentPath, []string{
		"-f", certificatePath, "-thumbprint", fingerprint, "-1", "-nochain", "-nocades",
	})
}

func (v *Verifier) finalVerificationArguments(signatureType domain.SignatureType, signaturePath, contentPath, certificatePath, fingerprint string) []string {
	return verificationArguments(signatureType, signaturePath, contentPath, []string{
		"-f", certificatePath, "-thumbprint", fingerprint, "-1", "-errchain", "-nonet", "-cadesbes",
	})
}

func (v *Verifier) fallbackVerificationArguments(signatureType domain.SignatureType, signaturePath, contentPath, certificatePath, fingerprint string) []string {
	return verificationArguments(signatureType, signaturePath, contentPath, []string{
		"-f", certificatePath, "-thumbprint", fingerprint, "-1", "-nochain", "-cadesbes",
	})
}

func verificationArguments(signatureType domain.SignatureType, signaturePath, contentPath string, policy []string) []string {
	arguments := []string{"-verify"}
	if signatureType == domain.TypeAttached {
		arguments = append(arguments, "-attached")
	} else {
		arguments = append(arguments, "-detached")
	}
	arguments = append(arguments, policy...)
	if signatureType == domain.TypeDetached {
		arguments = append(arguments, contentPath)
	}
	arguments = append(arguments, signaturePath)
	if signatureType == domain.TypeAttached {
		arguments = append(arguments, contentPath)
	}
	return arguments
}

func classifySignerProbe(result commandResult) (valid bool, skip bool, err error) {
	if !result.okCodes {
		return false, false, domain.Fail(domain.OutcomeUnknown)
	}
	if result.exitCode == 0 && isSuccessCode(result.codes) {
		return true, false, nil
	}
	if result.exitCode != 0 && len(result.codes) == 1 && result.codes[0] == invalidSignatureErrorCode {
		return false, false, nil
	}
	if result.exitCode != 0 && len(result.codes) == 1 && result.codes[0] == notSignerErrorCode {
		return false, true, nil
	}
	if len(result.codes) == 1 {
		return false, false, domain.Fail(domain.ProviderError)
	}
	return false, false, domain.Fail(domain.OutcomeUnknown)
}

func classifyFinalVerification(result commandResult) (bool, error) {
	if !result.okCodes {
		return false, domain.Fail(domain.OutcomeUnknown)
	}
	if result.exitCode == 0 && isSuccessCode(result.codes) {
		return true, nil
	}
	if result.exitCode != 0 && len(result.codes) == 1 && result.codes[0] == invalidSignatureErrorCode {
		return false, nil
	}
	if len(result.codes) == 1 {
		return false, domain.Fail(domain.ProviderError)
	}
	return false, domain.Fail(domain.OutcomeUnknown)
}

func isRevocationOffline(result commandResult) bool {
	if result.exitCode == 0 || !result.okCodes || len(result.codes) == 0 {
		return false
	}
	seen := map[string]struct{}{}
	for _, code := range result.codes {
		seen[code] = struct{}{}
	}
	_, ok := seen[revocationOfflineCode]
	return ok && len(seen) == 1
}

func isSuccessCode(codes []string) bool {
	return len(codes) == 1 && codes[0] == successErrorCode
}

func (v *Verifier) runSuccessfully(arguments []string, deadline time.Time) error {
	result, err := v.run(arguments, deadline)
	if err != nil {
		return err
	}
	if result.exitCode != 0 || !result.okCodes || !isSuccessCode(result.codes) {
		if result.okCodes && len(result.codes) == 1 {
			return domain.Fail(domain.ProviderError)
		}
		return domain.Fail(domain.OutcomeUnknown)
	}
	return nil
}

func (v *Verifier) run(arguments []string, deadline time.Time) (commandResult, error) {
	return (runner{path: v.cryptcpPath, timeout: v.timeout}).run(deadline, arguments)
}

func (v *Verifier) certificatesFromSignature(signature []byte, signaturePath, certificateBundlePath string, deadline time.Time) (map[string][]byte, error) {
	extracted, err := v.extractor.Extract(signature)
	if err == nil {
		return extracted, nil
	}
	if typed, ok := domain.AsError(err); !ok || typed.Failure != domain.InvalidSignatureStructure {
		return nil, err
	}
	if err := v.runSuccessfully([]string{
		"-copycert", "-f", signaturePath, "-all", "-nochain", "-df", certificateBundlePath,
	}, deadline); err != nil {
		return nil, err
	}
	return certificatesFromBundle(certificateBundlePath)
}

func (v *Verifier) assertAttachedContent(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return domain.Fail(domain.OutcomeUnknown)
	}
	if info.Size() > int64(v.maxContentBytes) {
		return domain.Fail(domain.InvalidSignatureStructure)
	}
	return nil
}
