package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type config struct {
	CertificateBase64  string `json:"certificateBase64"`
	EmitSuccessMarker  bool   `json:"emitSuccessMarker"`
	DelayMilliseconds  int    `json:"delayMilliseconds"`
	StaleCRLOnErrchain bool   `json:"staleCrlOnErrchain"`
}

func main() {
	cfg := config{EmitSuccessMarker: true}
	args := os.Args[1:]
	if len(args) > 0 && filepath.Ext(args[0]) == ".json" {
		raw, err := os.ReadFile(args[0])
		if err != nil {
			os.Exit(90)
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			os.Exit(90)
		}
		args = args[1:]
	} else {
		exe, err := os.Executable()
		if err == nil {
			if raw, err := os.ReadFile(exe + ".json"); err == nil {
				_ = json.Unmarshal(raw, &cfg)
			}
		}
	}

	if cfg.DelayMilliseconds > 0 {
		time.Sleep(time.Duration(cfg.DelayMilliseconds) * time.Millisecond)
	}

	certificate, err := base64.StdEncoding.DecodeString(cfg.CertificateBase64)
	if err != nil {
		certificate = nil
	}
	if len(args) == 0 {
		os.Exit(93)
	}

	expectedThumbprint := ""
	if len(certificate) > 0 {
		sum := sha1.Sum(certificate)
		expectedThumbprint = hex.EncodeToString(sum[:])
	}

	switch args[0] {
	case "-copycert":
		output, ok := valueAfter(args, "-df")
		if !ok || len(certificate) == 0 {
			os.Exit(90)
		}
		if hasArg(args, "-all") {
			if err := os.WriteFile(output, []byte(base64.StdEncoding.EncodeToString(certificate)+"\n"), 0o600); err != nil {
				os.Exit(90)
			}
			succeed(cfg.EmitSuccessMarker)
		}
		thumb, ok := valueAfter(args, "-thumbprint")
		if ok && thumb == expectedThumbprint {
			if err := os.WriteFile(output, certificate, 0o600); err != nil {
				os.Exit(90)
			}
			succeed(cfg.EmitSuccessMarker)
		}
		os.Exit(91)
	case "-verify":
		attached := hasArg(args, "-attached")
		detached := hasArg(args, "-detached")
		probe := hasArg(args, "-nocades")
		bes := hasArg(args, "-cadesbes")
		if attached == detached || boolToInt(probe)+boolToInt(bes) != 1 {
			os.Exit(92)
		}
		if probe && !hasArg(args, "-nochain") {
			os.Exit(92)
		}
		errchain := hasArg(args, "-errchain") && hasArg(args, "-nonet")
		offlineFallback := hasArg(args, "-nochain") && !hasArg(args, "-errchain")
		if bes && cfg.StaleCRLOnErrchain {
			if errchain {
				_, _ = os.Stderr.WriteString("[ErrorCode: 0x20000133]\n")
				os.Exit(1)
			}
			if !offlineFallback {
				os.Exit(92)
			}
		} else if bes && !errchain {
			os.Exit(92)
		}
		thumb, ok := valueAfter(args, "-thumbprint")
		if !ok || thumb != expectedThumbprint {
			os.Exit(92)
		}
		if attached {
			output := args[len(args)-1]
			if err := os.WriteFile(output, []byte("verified content"), 0o600); err != nil {
				os.Exit(92)
			}
		}
		succeed(cfg.EmitSuccessMarker)
	default:
		os.Exit(93)
	}
}

func succeed(emit bool) {
	if emit {
		_, _ = os.Stdout.WriteString("[ErrorCode: 0x00000000]\n")
	}
	os.Exit(0)
}

func hasArg(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}

func valueAfter(args []string, name string) (string, bool) {
	for i, arg := range args {
		if arg == name && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
