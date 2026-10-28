package router

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// testResolver is a valid DNS journal entry for the zone on this OS.
func testResolver(zone string) string {
	switch runtime.GOOS {
	case "windows":
		return zone
	case "darwin":
		return "/etc/resolver/" + zone
	}
	return "domain tun0 " + zone
}

// fakeBackend records what is asked of the OS.
type fakeBackend struct {
	mu        sync.Mutex
	log       []string // "dns <id>", "route <dest>", "flush"
	failRoute map[string]error
	block     chan struct{} // when set, DelRoute waits for it to be closed
}

func (f *fakeBackend) record(s string) {
	f.mu.Lock()
	f.log = append(f.log, s)
	f.mu.Unlock()
}

func (f *fakeBackend) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeBackend) AddRoute(r config.Route) error { f.record("addroute " + r.Dest); return nil }
func (f *fakeBackend) AddResolver(id string, _ []string) error {
	f.record("adddns " + id)
	return nil
}
func (f *fakeBackend) DelResolver(id string) error { f.record("dns " + id); return nil }
func (f *fakeBackend) FlushDNS()                   { f.record("flush") }
func (f *fakeBackend) DelRoute(r config.Route) error {
	if f.block != nil {
		<-f.block
	}
	f.record("route " + r.Dest)
	return f.failRoute[r.Dest]
}

// memStore is the journal in memory.
type memStore struct {
	mu          sync.Mutex
	raw         []byte
	status      config.JournalStatus
	saveErr     error
	saves       int
	panicOnLoad bool
}

func newMemStore(st *config.State) *memStore {
	s := &memStore{}
	if st != nil {
		s.raw, _ = json.Marshal(st)
	}
	return s
}

func (s *memStore) Load() (*config.State, []string, config.JournalStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.panicOnLoad {
		panic("journal exploded")
	}
	if s.panicOnLoad {
		panic("journal exploded")
	}
	st := &config.State{}
	if s.raw != nil {
		_ = json.Unmarshal(s.raw, st)
	}
	return st, nil, s.status
}

func (s *memStore) Save(st *config.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saves++
	s.raw, _ = json.Marshal(st)
	return nil
}

func (s *memStore) state() *config.State {
	st, _, _ := s.Load()
	return st
}

// fakeProcs: alive maps pid to start time.
type fakeProcs struct {
	self  config.Owner
	alive map[int]int64
}

func (p *fakeProcs) Self() config.Owner { return p.self }
func (p *fakeProcs) Alive(o config.Owner) bool {
	start, ok := p.alive[o.PID]
	return ok && (o.Start == 0 || start == o.Start)
}
func (p *fakeProcs) SameBoot(a, b string) bool { return a == "" || b == "" || a == b }

// fakeLock is the lock of one machine, shared by the Managers of "copies".
type fakeLock struct {
	mu   sync.Mutex
	held bool
}

func (l *fakeLock) take() (func() error, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return nil, fmt.Errorf("fake: %w", config.ErrLocked)
	}
	l.held = true
	return func() error {
		l.mu.Lock()
		l.held = false
		l.mu.Unlock()
		return nil
	}, nil
}

type rig struct {
	m     *Manager
	b     *fakeBackend
	store *memStore
	procs *fakeProcs
	lock  *fakeLock
}

// newRig is a Manager on fakes; the journal starts as st (nil: none).
func newRig(st *config.State) *rig {
	r := &rig{
		b:     &fakeBackend{failRoute: map[string]error{}},
		store: newMemStore(st),
		procs: &fakeProcs{self: config.Owner{PID: 100, Start: 5000, Boot: "boot-2"}, alive: map[int]int64{100: 5000}},
		lock:  &fakeLock{},
	}
	r.m = newManager(r.b, r.store, r.procs, r.lock.take)
	return r
}

// another is a second copy of the program on the same machine.
func (r *rig) another(pid int) *rig {
	o := &rig{b: &fakeBackend{failRoute: map[string]error{}}, store: r.store, lock: r.lock,
		procs: &fakeProcs{self: config.Owner{PID: pid, Start: 7000, Boot: "boot-2"}, alive: r.procs.alive}}
	o.procs.alive[pid] = 7000
	o.m = newManager(o.b, o.store, o.procs, o.lock.take)
	return o
}

func homeRoutes() []config.Route {
	return []config.Route{
		{Dest: "0.0.0.0/1", Iface: "wghome", Via: ViaHome},
		{Dest: "128.0.0.0/1", Iface: "wghome", Via: ViaHome},
	}
}

func corpRoute() config.Route {
	return config.Route{Dest: "10.10.0.0/16", Iface: "wgcorp", Via: ViaCorp}
}

// sessionJournal is a journal of a session whose owner is pid (start 4000, boot-2).
func sessionJournal(pid int, mode string) *config.State {
	return &config.State{
		Version:   config.JournalVersion,
		Owner:     &config.Owner{PID: pid, Start: 4000, Boot: "boot-2"},
		Mode:      mode,
		Routes:    append([]config.Route{corpRoute()}, homeRoutes()...),
		Resolvers: []string{testResolver("corp.example")},
		Sig:       "sig",
	}
}

// before reports whether every entry of log with prefix a comes before every entry with prefix b.
func before(log []string, a, b string) bool {
	lastA, firstB := -1, len(log)
	for i, l := range log {
		if strings.HasPrefix(l, a) {
			lastA = i
		}
		if strings.HasPrefix(l, b) && i < firstB {
			firstB = i
		}
	}
	return lastA >= 0 && firstB < len(log) && lastA < firstB
}

func (p *fakeProcs) AliveExact(o config.Owner) bool {
	start, ok := p.alive[o.PID]
	return ok && o.Start != 0 && start == o.Start
}
