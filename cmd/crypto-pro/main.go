package main

import (
	"crypto-pro/internal/config"
	"crypto-pro/internal/cryptopro"
	"crypto-pro/internal/domain"
	"crypto-pro/internal/httpapi"
	"crypto-pro/internal/validate"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := config.FromEnv()
	var verifier domain.Verifier
	switch cfg.Verifier {
	case config.VerifierSynthetic:
		verifier = cryptopro.NewSyntheticVerifier()
		logger.Info("cryptopro.verifier", "mode", "synthetic")
	default:
		verifier = cryptopro.NewVerifier(cryptopro.Options{
			CryptcpPath:        cfg.CryptcpPath,
			Timeout:            cfg.Timeout,
			Deadline:           cfg.Deadline,
			AllowStaleCRL:      cfg.AllowStaleCRL,
			MaxContentBytes:    validate.MaxContentBytes,
			CertificateExtract: cryptopro.NewCMSExtractor(),
		})
		logger.Info("cryptopro.verifier", "mode", "cryptopro", "enabled", cfg.VerificationEnabled)
	}

	service := validate.NewService(verifier, cfg.VerificationEnabled)
	handler := httpapi.NewHandler(service, logger)
	server := httpapi.NewServer(cfg.Addr, handler)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("cryptopro.listen", "addr", cfg.Addr)
		errCh <- server.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logger.Info("cryptopro.shutdown", "signal", sig.String())
		_ = server.Close()
	case err := <-errCh:
		if err != nil {
			logger.Error("cryptopro.server", "failure", "unavailable")
			os.Exit(1)
		}
	}
}
