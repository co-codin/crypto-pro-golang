package httpapi

import (
	"net/http"
	"time"
)

const validatePath = "/api/crypto/v1/validate"

func NewServer(addr string, handler http.Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(validatePath, handler)
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}
