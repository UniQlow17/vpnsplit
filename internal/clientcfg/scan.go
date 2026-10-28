package clientcfg

import (
	"net/netip"
	"runtime"
	"sync"
	"time"
)

// Result is everything Scan found. A part that could not be read is empty
// (and, where it matters, not Known): finding nothing is not an error.
type Result struct {
	Proxy Proxy

	Tun        []TunCfg       // the configs of sing-box, Hiddify and Mihomo that were read
	FakeRanges []netip.Prefix // the fake-ip ranges of all of them, valid and without duplicates

	GPOKnown bool // the Group Policy key could be asked (Windows)
	GPONRPT  int  // how many NRPT rules Group Policy has

	OvpnBlockDNS string // "" or the file (name) in which block-outside-dns was found

	CiscoFailClosed bool // a profile of Cisco AnyConnect / Secure Client fails closed
	CiscoAlwaysOn   bool
}

// scanFn is Scan; a variable so that the tests can replace the slow part.
var scanFn = Scan

// scanFilesFn is ScanFiles, likewise.
var scanFilesFn = ScanFiles

// Scan reads the settings. It starts no process except the proxy query of the
// OS (scutil, gsettings) and reads only: it changes nothing. The proxy query
// is the slow and the only one that can hang (a D-Bus without an answer), so it
// is not part of ScanFiles.
func Scan() Result {
	r := ScanFiles()
	r.Proxy = readProxy()
	return r
}

// ScanFiles is Scan without the proxy: the files of the clients, the Group
// Policy key, the profiles of Cisco. It starts no process. The fake-ip ranges
// for the apply come from here, so they never wait for a tool of the OS.
func ScanFiles() Result {
	var r Result
	r.GPOKnown, r.GPONRPT = readGPONRPT()
	r.scanTun()
	if runtime.GOOS == "windows" {
		r.scanOvpn()
	}
	r.scanCisco()
	return r
}

// flightCache keeps the last result of fn and renews it in the background:
// one run at a time (single flight), and the mutex is held only to look at or
// to store the fields, never while fn runs, so a reader is not blocked by a
// run that hangs.
type flightCache struct {
	fn     func() Result
	mu     sync.Mutex
	at     time.Time
	have   bool
	res    Result
	flight chan struct{} // non-nil while a run is going; closed when it is over
}

// get returns the result if it is younger than maxAge. Otherwise it starts a
// run (unless one is going) and waits for it at most wait (0: not at all); the
// previous result (empty if there was none) is returned when the run is not over.
func (c *flightCache) get(maxAge, wait time.Duration) Result {
	c.mu.Lock()
	if c.have && time.Since(c.at) < maxAge {
		r := c.res
		c.mu.Unlock()
		return r
	}
	fl := c.flight
	if fl == nil {
		fl = make(chan struct{})
		c.flight = fl
		go c.run(fl)
	}
	c.mu.Unlock()
	if wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-fl:
		case <-t.C:
		}
		t.Stop()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.res
}

func (c *flightCache) run(fl chan struct{}) {
	var r Result
	ok := false
	defer func() {
		_ = recover() // the settings are an extra: a broken reader must not stop the program
		c.mu.Lock()
		if ok {
			c.res, c.at, c.have = r, time.Now(), true
		}
		c.flight = nil
		c.mu.Unlock()
		close(fl)
	}()
	r = c.fn()
	ok = true
}

var (
	fullCache  = &flightCache{fn: func() Result { return scanFn() }}
	filesCache = &flightCache{fn: func() Result { return scanFilesFn() }}
)

// scanWait is how long Cached waits for a run: the caller has the answer in a
// moment or goes on without it.
var scanWait = 2 * time.Second

// Cached is Scan, repeated at most once in maxAge: the files and the registry
// do not change every two seconds, and the poll of the interface should not read
// them. It waits for a run no longer than scanWait; if the run is not over
// (a hung tool), the previous result is returned and the run goes on in the background.
func Cached(maxAge time.Duration) Result { return fullCache.get(maxAge, scanWait) }

// filesWait is the wait for the files when nothing has been read yet.
var filesWait = time.Second

// Files returns the last ScanFiles result without waiting for a new one (a
// stale result is renewed in the background). Before the first read it waits
// for it up to filesWait: a read of a few small files.
func Files() Result {
	fresh := filesCache.get(clientScanAge, 0)
	filesCache.mu.Lock()
	have := filesCache.have
	filesCache.mu.Unlock()
	if !have {
		fresh = filesCache.get(clientScanAge, filesWait)
	}
	return fresh
}

// clientScanAge is how old the result of ScanFiles may be before it is renewed.
const clientScanAge = 30 * time.Second
