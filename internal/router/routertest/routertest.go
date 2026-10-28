// Package routertest is a Manager on fakes: no OS tool is run and no file is
// written. It is for the tests of the packages that use router.Manager.
package routertest

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/router"
)

// Rig is a Manager with its fakes. Self is PID 100, boot-2.
type Rig struct {
	M      *router.Manager
	Mu     sync.Mutex
	Log    []string // "dns <id>", "route <dest>", "flush"
	Fail   map[string]error
	raw    []byte
	held   bool
	Alive  map[int]int64
	Status config.JournalStatus
}

// New returns a Rig whose journal starts as st (nil: none).
func New(st *config.State) *Rig {
	r := &Rig{Fail: map[string]error{}, Alive: map[int]int64{100: 5000}}
	if st != nil {
		r.raw, _ = json.Marshal(st)
	}
	r.M = router.NewManagerFor(backend{r}, store{r}, procs{r}, r.lock)
	return r
}

// Calls is what was asked of the OS.
func (r *Rig) Calls() []string {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	return append([]string(nil), r.Log...)
}

// State is the journal now.
func (r *Rig) State() *config.State {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	st := &config.State{}
	if r.raw != nil {
		_ = json.Unmarshal(r.raw, st)
	}
	return st
}

// Held reports whether the lock is taken.
func (r *Rig) Held() bool {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	return r.held
}

func (r *Rig) record(s string) {
	r.Mu.Lock()
	r.Log = append(r.Log, s)
	r.Mu.Unlock()
}

func (r *Rig) lock() (func() error, error) {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	if r.held {
		return nil, fmt.Errorf("fake: %w", config.ErrLocked)
	}
	r.held = true
	return func() error {
		r.Mu.Lock()
		r.held = false
		r.Mu.Unlock()
		return nil
	}, nil
}

// Resolver is a valid DNS journal entry for the zone on this OS.
func Resolver(zone string) string {
	switch runtime.GOOS {
	case "windows":
		return zone
	case "darwin":
		return "/etc/resolver/" + zone
	}
	return "domain tun0 " + zone
}

// Journal is a journal of an owner that is gone (pid 4242, boot-2) with a
// corp route, the two routes of the full home tunnel and one DNS entry.
func Journal(mode string) *config.State {
	return &config.State{
		Version: config.JournalVersion,
		Owner:   &config.Owner{PID: 4242, Start: 4000, Boot: "boot-2"},
		Mode:    mode,
		Routes: []config.Route{
			{Dest: "10.10.0.0/16", Iface: "wgcorp", Via: router.ViaCorp},
			{Dest: "0.0.0.0/1", Iface: "wghome", Via: router.ViaHome},
			{Dest: "128.0.0.0/1", Iface: "wghome", Via: router.ViaHome},
		},
		Resolvers: []string{Resolver("corp.example")},
		Sig:       "sig",
	}
}

type backend struct{ r *Rig }

func (b backend) AddRoute(r config.Route) error { b.r.record("addroute " + r.Dest); return nil }
func (b backend) AddResolver(id string, _ []string) error {
	b.r.record("adddns " + id)
	return nil
}
func (b backend) DelResolver(id string) error { b.r.record("dns " + id); return nil }
func (b backend) FlushDNS()                   { b.r.record("flush") }
func (b backend) DelRoute(r config.Route) error {
	b.r.record("route " + r.Dest)
	b.r.Mu.Lock()
	defer b.r.Mu.Unlock()
	return b.r.Fail[r.Dest]
}

type store struct{ r *Rig }

func (s store) Load() (*config.State, []string, config.JournalStatus) {
	return s.r.State(), nil, s.r.Status
}

func (s store) Save(st *config.State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	s.r.Mu.Lock()
	s.r.raw = b
	s.r.Mu.Unlock()
	return nil
}

type procs struct{ r *Rig }

func (p procs) Self() config.Owner { return config.Owner{PID: 100, Start: 5000, Boot: "boot-2"} }
func (p procs) Alive(o config.Owner) bool {
	start, ok := p.r.Alive[o.PID]
	return ok && (o.Start == 0 || start == o.Start)
}
func (p procs) AliveExact(o config.Owner) bool {
	start, ok := p.r.Alive[o.PID]
	return ok && o.Start != 0 && start == o.Start
}
func (p procs) SameBoot(a, b string) bool { return a == "" || b == "" || a == b }

// Calls with prefix.
func Count(log []string, prefix string) int {
	n := 0
	for _, l := range log {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}
