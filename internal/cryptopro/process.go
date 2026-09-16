package cryptopro

import (
	"bytes"
	"context"
	"crypto-pro/internal/domain"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type commandResult struct {
	exitCode int
	codes    []string
	okCodes  bool
}

type runner struct {
	path    string
	timeout time.Duration
}

func (r runner) run(deadline time.Time, args []string) (commandResult, error) {
	info, err := os.Stat(r.path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return commandResult{}, domain.Fail(domain.Unavailable)
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return commandResult{}, domain.Fail(domain.Timeout)
	}
	timeout := r.timeout
	if timeout <= 0 || timeout > remaining {
		timeout = remaining
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.path, args...)
	cmd.Env = sanitizedEnvironment()
	cmd.Stdin = bytes.NewReader(nil)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return commandResult{}, domain.Fail(domain.Unavailable)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return commandResult{}, domain.Fail(domain.Unavailable)
	}

	stdoutScanner := NewErrorCodeScanner()
	stderrScanner := NewErrorCodeScanner()

	if err := cmd.Start(); err != nil {
		return commandResult{}, domain.Fail(domain.Unavailable)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go scanStream(&wg, stdout, stdoutScanner)
	go scanStream(&wg, stderr, stderrScanner)

	waitErr := cmd.Wait()
	wg.Wait()

	if ctx.Err() == context.DeadlineExceeded {
		return commandResult{}, domain.Fail(domain.Timeout)
	}
	if deadline.Before(time.Now()) && waitErr != nil {
		return commandResult{}, domain.Fail(domain.Timeout)
	}

	exitCode := 0
	if waitErr != nil {
		exitError, ok := waitErr.(*exec.ExitError)
		if !ok {
			return commandResult{}, domain.Fail(domain.OutcomeUnknown)
		}
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return commandResult{}, domain.Fail(domain.Interrupted)
		}
		exitCode = exitError.ExitCode()
		if exitCode < 0 {
			return commandResult{}, domain.Fail(domain.OutcomeUnknown)
		}
	}

	stdoutCodes := stdoutScanner.Codes()
	stderrCodes := stderrScanner.Codes()
	if stdoutCodes == nil || stderrCodes == nil {
		return commandResult{exitCode: exitCode, okCodes: false}, nil
	}
	return commandResult{
		exitCode: exitCode,
		codes:    append(append([]string{}, stdoutCodes...), stderrCodes...),
		okCodes:  true,
	}, nil
}

func scanStream(wg *sync.WaitGroup, r io.Reader, scanner *ErrorCodeScanner) {
	defer wg.Done()
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			scanner.Consume(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func sanitizedEnvironment() []string {
	env := []string{"LANG=C", "LC_ALL=C"}
	for _, name := range []string{"HOME", "PATH", "TZ"} {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}
