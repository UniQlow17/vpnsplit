package clientcfg

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestMain lets the test binary act as the tool that hangs.
func TestMain(m *testing.M) {
	switch os.Getenv("CLIENTCFG_HELPER") {
	case "sleep":
		time.Sleep(2 * time.Second) // short: a child that outlives the test holds the test binary
		os.Exit(0)
	case "spawn":
		// leaves a child that keeps the output pipe open, then waits too
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), "CLIENTCFG_HELPER=sleep")
		c.Stdout = os.Stdout
		_ = c.Start()
		time.Sleep(time.Minute) // killed by the test
		os.Exit(0)
	case "echo":
		os.Stdout.WriteString("hello")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helper(mode string) *exec.Cmd {
	c := exec.Command(os.Args[0])
	c.Env = append(os.Environ(), "CLIENTCFG_HELPER="+mode)
	return c
}

func TestRunLimitedOutput(t *testing.T) {
	out, err := runLimited(helper("echo"))
	if err != nil || out != "hello" {
		t.Errorf("%q %v", out, err)
	}
}

func TestRunLimitedHungTool(t *testing.T) {
	old := toolTimeout
	toolTimeout = 200 * time.Millisecond
	t.Cleanup(func() { toolTimeout = old })
	for _, mode := range []string{"sleep", "spawn"} {
		start := time.Now()
		_, err := runLimited(helper(mode))
		if err == nil {
			t.Errorf("%s: no error", mode)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v", mode, d)
		}
	}
	if runtime.GOOS == "windows" {
		time.Sleep(2500 * time.Millisecond) // the child of "spawn" is not killed here: wait until it is gone
	}
}

// A scan that never ends must not hold the reader: Cached waits a bounded
// time and Files does not wait once there is a result.
func TestHungScanDoesNotBlock(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	var runs atomic.Int32
	c := &flightCache{fn: func() Result {
		runs.Add(1)
		<-block
		return Result{GPONRPT: 7}
	}}
	start := time.Now()
	r := c.get(time.Hour, 100*time.Millisecond)
	if d := time.Since(start); d > 3*time.Second || r.GPONRPT != 0 {
		t.Errorf("hung: %v %+v", d, r)
	}
	// readers are not blocked by the run, and no second run is started
	start = time.Now()
	for range 5 {
		c.get(time.Hour, 0)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("readers blocked: %v", d)
	}
	if runs.Load() != 1 {
		t.Errorf("runs: %d", runs.Load())
	}
}

func TestFlightCacheReuses(t *testing.T) {
	var runs atomic.Int32
	c := &flightCache{fn: func() Result { runs.Add(1); return Result{GPONRPT: int(runs.Load())} }}
	if r := c.get(time.Hour, time.Second); r.GPONRPT != 1 {
		t.Errorf("first: %+v", r)
	}
	if r := c.get(time.Hour, time.Second); r.GPONRPT != 1 || runs.Load() != 1 {
		t.Errorf("not reused: %+v %d", r, runs.Load())
	}
	// stale: the old result at once, the new one after the run
	if r := c.get(0, time.Second); r.GPONRPT != 2 {
		t.Errorf("not renewed: %+v", r)
	}
}

func TestFlightCachePanicIsContained(t *testing.T) {
	c := &flightCache{fn: func() Result { panic("boom") }}
	_ = c.get(time.Hour, time.Second)
	// the empty result counts: a reader does not start the broken run again
	c.fn = func() Result { return Result{GPONRPT: 3} }
	start := time.Now()
	if r := c.get(time.Hour, time.Second); r.GPONRPT != 0 || r.Stale || time.Since(start) > 500*time.Millisecond {
		t.Errorf("after a panic: %+v", r)
	}
	// once it is old, the run is made again
	if r := c.get(0, time.Second); r.GPONRPT != 3 {
		t.Errorf("not renewed after a panic: %+v", r)
	}
}

func TestFsReaderRefusesLinkedParents(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "mihomo", "config.yaml"), "tun:\n  enable: true\n")
	if err := os.Symlink(outside, filepath.Join(home, ".config")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	fs := fsReader{bases: []string{home}}
	if _, err := fs.read(filepath.Join(home, ".config", "mihomo", "config.yaml"), false, 1<<20); err == nil {
		t.Error("a file behind a linked parent directory was read")
	}
	write(t, filepath.Join(home, "plain", "x.json"), "{}")
	if _, err := fs.read(filepath.Join(home, "plain", "x.json"), false, 1<<20); err != nil {
		t.Errorf("a plain file: %v", err)
	}
	if _, err := fs.read(filepath.Join(outside, "mihomo", "config.yaml"), false, 1<<20); err == nil {
		t.Error("a file outside the profile was read")
	}
}

func TestMachineFilesNeedSystemOwner(t *testing.T) {
	// a file made by the test user is not the system's: refused (a test run as root excepted)
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	write(t, p, "{}")
	fs := fsReader{}
	if os.Geteuid() == 0 {
		t.Skip("root owns the files here")
	}
	if _, err := fs.read(p, true, 100); err == nil {
		t.Error("a machine file owned by the user was read")
	}
	if got := fs.glob(dir, true, "*.json"); len(got) != 0 {
		t.Errorf("a machine directory owned by the user was listed: %v", got)
	}
}

// The public readers with a hung reader behind them: Cached waits scanWait at
// most, Files waits filesWait before the first result and not at all later.
func TestPublicReadersWithHungScan(t *testing.T) {
	block := make(chan struct{})
	oldFull, oldFiles, oldWait, oldFilesWait := fullCache, filesCache, scanWait, filesWait
	t.Cleanup(func() {
		close(block)
		fullCache, filesCache, scanWait, filesWait = oldFull, oldFiles, oldWait, oldFilesWait
	})
	hang := func() Result { <-block; return Result{} }
	fullCache, filesCache = &flightCache{fn: hang}, &flightCache{fn: hang}
	scanWait, filesWait = 100*time.Millisecond, 100*time.Millisecond

	start := time.Now()
	_ = Cached(time.Minute)
	_ = Files()
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("readers held by a hung scan: %v", d)
	}
	// with a result in hand, Files does not wait for the renewal
	filesCache = &flightCache{fn: hang, have: true, res: Result{GPONRPT: 4}, at: time.Now().Add(-time.Hour)}
	filesWait = time.Hour
	start = time.Now()
	if r := Files(); r.GPONRPT != 4 || time.Since(start) > time.Second {
		t.Errorf("Files waited or lost the result: %+v %v", r, time.Since(start))
	}
}
