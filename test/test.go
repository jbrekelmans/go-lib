package test

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	log "github.com/sirupsen/logrus"
)

// testingLogRedirector is inspired by https://github.com/sirupsen/logrus/issues/834
type testingLogRedirector struct {
	lineBuffer     bytes.Buffer
	logger         *log.Logger
	originalOutput io.Writer
	t              *testing.T
}

// Dispose is documented in RedirectLogs.
func (t *testingLogRedirector) Dispose() {
	rest := t.lineBuffer.Bytes()
	if len(rest) > 0 {
		t.t.Log(string(rest))
	}
	t.logger.SetOutput(t.originalOutput)
}

// Write implements the io.Writer interface.
func (t *testingLogRedirector) Write(p []byte) (n int, err error) {
	n, _ = t.lineBuffer.Write(p)
	for {
		advance, token, _ := bufio.ScanLines(t.lineBuffer.Bytes(), false)
		if advance == 0 {
			return
		}
		t.t.Log(string(token))
		t.lineBuffer.Next(advance)
	}
}

// Disposable represents a resource that needs to be explicitly freed.
type Disposable interface {
	Dispose()
}

// RedirectLogs redirects the output of logrus' standard logger to a testing.T and returns a Disposable that restores the standard logger's
// output to the output when RedirectLogs was called once Dispose is called.
func RedirectLogs(t *testing.T) Disposable {
	logger := log.StandardLogger()
	d := &testingLogRedirector{
		logger:         logger,
		originalOutput: logger.Out,
		t:              t,
	}
	if !testing.Verbose() {
		d.logger.SetOutput(d)
	}
	return d
}
