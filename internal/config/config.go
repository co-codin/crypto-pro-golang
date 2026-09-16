package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	VerifierCryptoPro = "cryptopro"
	VerifierSynthetic = "synthetic"
)

type Config struct {
	Addr                string
	VerificationEnabled bool
	Verifier            string
	CryptcpPath         string
	Timeout             time.Duration
	Deadline            time.Duration
	AllowStaleCRL       bool
}

func FromEnv() Config {
	timeoutSeconds := envFloat("CRYPTOPRO_PROCESS_TIMEOUT_SECONDS", 30)
	deadlineSeconds := envFloat("CRYPTOPRO_REQUEST_DEADLINE_SECONDS", 45)
	verifier := strings.ToLower(strings.TrimSpace(env("CRYPTOPRO_VERIFIER", VerifierCryptoPro)))
	if verifier != VerifierSynthetic {
		verifier = VerifierCryptoPro
	}
	return Config{
		Addr:                env("HTTP_ADDR", ":18080"),
		VerificationEnabled: envBool("CRYPTOPRO_SIGNATURE_VERIFY_ENABLED"),
		Verifier:            verifier,
		CryptcpPath:         env("CRYPTOPRO_CRYPTCP_PATH", "/opt/cprocsp/bin/amd64/cryptcp"),
		Timeout:             time.Duration(timeoutSeconds * float64(time.Second)),
		Deadline:            time.Duration(deadlineSeconds * float64(time.Second)),
		AllowStaleCRL:       envBool("CRYPTOPRO_STALE_CRL_FALLBACK"),
	}
}

func env(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func envBool(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envFloat(name string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
