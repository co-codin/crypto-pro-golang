package httpapi

import (
	"crypto-pro/internal/domain"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	invalidRequestMessage   = "Invalid signature validation request."
	invalidSignatureCode    = "0x200001F9"
	invalidSignatureMessage = "The signature is invalid."
	disabledMessage         = "CryptoPro signature verification is disabled."
	unavailableMessage      = "CryptoPro is unavailable."
	timeoutMessage          = "CryptoPro did not complete signature verification in time."
	interruptedMessage      = "CryptoPro did not complete signature verification."
	providerMessage         = "CryptoPro could not verify the signature."
	unknownOutcomeMessage   = "The signature verification outcome could not be determined safely."
	certificateMetaMessage  = "CryptoPro returned unsupported certificate metadata."
)

// Responder maps use-case results and expected failures onto the OpenAPI wire.
type Responder struct{}

func NewResponder() Responder {
	return Responder{}
}

func (Responder) NewGUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (r Responder) InvalidRequest(w http.ResponseWriter, guid string) {
	r.writeError(w, http.StatusBadRequest, invalidRequestMessage, guid)
}

func (r Responder) Result(w http.ResponseWriter, result domain.Result, guid string) {
	if result.Valid {
		r.writeJSON(w, http.StatusOK, map[string]any{
			"isSignValid": true,
			"signInfo":    result.SignInfo,
		}, guid)
		return
	}
	r.writeJSON(w, http.StatusOK, map[string]any{
		"isSignValid": false,
		"error": map[string]any{
			"code":    invalidSignatureCode,
			"message": invalidSignatureMessage,
		},
	}, guid)
}

func (r Responder) Failure(w http.ResponseWriter, err *domain.Error, guid string) {
	message, status := mapFailure(err.Failure)
	r.writeError(w, status, message, guid)
}

func mapFailure(failure domain.Failure) (string, int) {
	switch failure {
	case domain.InvalidSignatureInput, domain.InvalidSignatureStructure:
		return invalidRequestMessage, http.StatusBadRequest
	case domain.CertificateMetadataError:
		return certificateMetaMessage, http.StatusBadGateway
	case domain.Disabled:
		return disabledMessage, http.StatusServiceUnavailable
	case domain.Unavailable:
		return unavailableMessage, http.StatusServiceUnavailable
	case domain.Timeout:
		return timeoutMessage, http.StatusGatewayTimeout
	case domain.Interrupted:
		return interruptedMessage, http.StatusServiceUnavailable
	case domain.ProviderError:
		return providerMessage, http.StatusBadGateway
	default:
		return unknownOutcomeMessage, http.StatusServiceUnavailable
	}
}

func (r Responder) writeError(w http.ResponseWriter, status int, message, guid string) {
	r.writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    status,
			"message": message,
		},
	}, guid)
}

func (Responder) writeJSON(w http.ResponseWriter, status int, body any, guid string) {
	payload, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "encoding error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Guid", guid)
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}
