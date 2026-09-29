package testsupport

import (
	"context"
	"crypto-pro/internal/domain"
	"log/slog"
	"sync"
)

type RecordingVerifier struct {
	Result domain.Result
	Err    error
	mu     sync.Mutex
	Calls  int
	Type   domain.SignatureType
	Sign   []byte
	File   []byte
}

func (r *RecordingVerifier) Verify(signatureType domain.SignatureType, signature []byte, content []byte) (domain.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Calls++
	r.Type = signatureType
	r.Sign = append([]byte(nil), signature...)
	if content != nil {
		r.File = append([]byte(nil), content...)
	} else {
		r.File = nil
	}
	if r.Err != nil {
		return domain.Result{}, r.Err
	}
	return r.Result, nil
}

type LogRecord struct {
	Level   slog.Level
	Message string
	Attrs   map[string]any
}

type RecordingHandler struct {
	mu      sync.Mutex
	Records []LogRecord
}

func (h *RecordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *RecordingHandler) Handle(_ context.Context, rec slog.Record) error {
	attrs := map[string]any{}
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Records = append(h.Records, LogRecord{Level: rec.Level, Message: rec.Message, Attrs: attrs})
	return nil
}

func (h *RecordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *RecordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *RecordingHandler) Snapshot() []LogRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]LogRecord, len(h.Records))
	copy(out, h.Records)
	return out
}
