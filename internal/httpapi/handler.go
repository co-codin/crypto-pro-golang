package httpapi

import (
	"crypto-pro/internal/domain"
	"crypto-pro/internal/validate"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"
)

// Handler is the thin HTTP boundary for POST /api/crypto/v1/validate.
type Handler struct {
	service   *validate.Service
	responder Responder
	logger    *slog.Logger
}

func NewHandler(service *validate.Service, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		service:   service,
		responder: NewResponder(),
		logger:    logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	guid := h.responder.NewGUID()
	started := time.Now()
	if r.Method != http.MethodPost {
		h.log(guid, started, "", "error", "invalid_request")
		h.responder.InvalidRequest(w, guid)
		return
	}
	if !isJSON(r.Header.Get("Content-Type")) {
		h.log(guid, started, "", "error", "invalid_request")
		h.responder.InvalidRequest(w, guid)
		return
	}

	limited := http.MaxBytesReader(w, r.Body, validate.MaxRequestBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		h.log(guid, started, "", "error", "invalid_request")
		h.responder.InvalidRequest(w, guid)
		return
	}

	req, err := validate.ParseRequest(body)
	if err != nil {
		h.log(guid, started, "", "error", "invalid_request")
		h.responder.InvalidRequest(w, guid)
		return
	}

	result, err := h.service.Execute(req.Type, req.Sign, req.File)
	if typed, ok := domain.AsError(err); ok {
		h.log(guid, started, string(req.Type), "error", string(typed.Failure))
		h.responder.Failure(w, typed, guid)
		return
	}
	if err != nil {
		h.log(guid, started, string(req.Type), "error", string(domain.OutcomeUnknown))
		h.responder.Failure(w, domain.Fail(domain.OutcomeUnknown), guid)
		return
	}

	outcome := "invalid"
	if result.Valid {
		outcome = "valid"
	}
	h.log(guid, started, string(req.Type), outcome, "")
	h.responder.Result(w, result, guid)
}

func (h *Handler) log(guid string, started time.Time, signatureType, result, failure string) {
	durationMs := float64(time.Since(started).Microseconds()) / 1000.0
	var format any
	var typ any
	if signatureType == "" {
		format = nil
		typ = nil
	} else {
		format = "bes"
		typ = signatureType
	}
	var fail any
	if failure == "" {
		fail = nil
	} else {
		fail = failure
	}
	attrs := []any{
		"x_guid", guid,
		"failure", fail,
		"type", typ,
		"format", format,
		"result", result,
		"duration_ms", durationMs,
	}
	if failure == "" {
		h.logger.Info("cryptopro.signature_validation", attrs...)
		return
	}
	h.logger.Warn("cryptopro.signature_validation", attrs...)
}

func isJSON(contentType string) bool {
	if contentType == "" {
		return false
	}
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.EqualFold(media, "application/json")
}
