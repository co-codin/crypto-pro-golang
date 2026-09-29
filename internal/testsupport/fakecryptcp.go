package testsupport

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type FakeCryptcpConfig struct {
	Certificate        []byte
	EmitSuccessMarker  bool
	DelayMilliseconds  int
	StaleCRLOnErrchain bool
}

var (
	fakeOnce sync.Once
	fakeBin  string
	fakeErr  error
)

func FakeCryptcp(t *testing.T, cfg FakeCryptcpConfig) string {
	t.Helper()
	bin := builtFakeCryptcp(t)
	dir := t.TempDir()
	if cfg.Certificate == nil {
		cfg.Certificate = LeafDER()
	}
	sidecar, err := json.Marshal(map[string]any{
		"certificateBase64":  base64.StdEncoding.EncodeToString(cfg.Certificate),
		"emitSuccessMarker":  cfg.EmitSuccessMarker,
		"delayMilliseconds":  cfg.DelayMilliseconds,
		"staleCrlOnErrchain": cfg.StaleCRLOnErrchain,
	})
	if err != nil {
		t.Fatalf("marshal fake cryptcp config: %v", err)
	}
	configPath := filepath.Join(dir, "fake-cryptcp.json")
	if err := os.WriteFile(configPath, sidecar, 0o600); err != nil {
		t.Fatalf("write fake cryptcp config: %v", err)
	}
	wrapper := filepath.Join(dir, "cryptcp")
	script := "#!/bin/sh\nexec " + shellQuote(bin) + " " + shellQuote(configPath) + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake cryptcp wrapper: %v", err)
	}
	return wrapper
}

func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'"'"'`) + "'"
}

func builtFakeCryptcp(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		root := moduleRoot()
		dir, err := os.MkdirTemp("", "fake-cryptcp-bin-")
		if err != nil {
			fakeErr = err
			return
		}
		out := filepath.Join(dir, "cryptcp")
		cmd := exec.Command("go", "build", "-o", out, "./cmd/fake-cryptcp")
		cmd.Dir = root
		cmd.Stderr = os.Stderr
		fakeErr = cmd.Run()
		fakeBin = out
	})
	if fakeErr != nil {
		t.Fatalf("build fake cryptcp: %v", fakeErr)
	}
	return fakeBin
}

func moduleRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if ok {
		dir := filepath.Dir(file)
		for i := 0; i < 6; i++ {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
			dir = filepath.Dir(dir)
		}
	}
	wd, _ := os.Getwd()
	return wd
}
