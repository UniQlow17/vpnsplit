package clientcfg

import (
	"bytes"
	"errors"
	"os/exec"
	"time"
)

// maxToolOutput bounds what is taken from a system tool.
const maxToolOutput = 1 << 20

// toolTimeout is how long a system tool may take: the answer is optional, the
// poll of the interface must not wait for a hung D-Bus. A variable so that
// the tests do not wait for seconds.
var toolTimeout = 3 * time.Second

// toolWaitDelay is how long, after the tool was killed (or has exited), the
// pipes of its output are waited for: a child that keeps the pipe open (the
// tool started something and left) must not hold the caller.
const toolWaitDelay = 500 * time.Millisecond

type limitedBuffer struct {
	bytes.Buffer
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxToolOutput {
		b.over = true
		return len(p), nil // dropped
	}
	return b.Buffer.Write(p)
}

// runLimited runs cmd (made by sysexec) and returns its standard output; the
// run is stopped after toolTimeout (with the processes it started, where the
// OS allows: see setGroup), the output is cut at maxToolOutput. It returns no
// later than toolTimeout + toolWaitDelay + a second, whatever the tool does.
func runLimited(cmd *exec.Cmd) (string, error) {
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.WaitDelay = toolWaitDelay
	setGroup(cmd)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t := time.NewTimer(toolTimeout)
	defer t.Stop()
	select {
	case err := <-done:
		// ErrWaitDelay: the tool ended well, a child it left kept the pipe
		// open; what was written until then is the answer
		if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
			return "", err
		}
	case <-t.C:
		killGroup(cmd)
		select {
		case <-done:
		case <-time.After(toolWaitDelay + time.Second):
		}
		return "", errors.New("timeout")
	}
	if out.over {
		return "", errors.New("output too long")
	}
	return out.String(), nil
}
