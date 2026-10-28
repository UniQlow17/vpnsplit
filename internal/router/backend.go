package router

import (
	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/sysproc"
)

// Backend is what the OS is asked to do. The real one (osBackend) talks to
// the routing API of each OS (iphlpapi, rtnetlink; the route tool on macOS)
// and runs the system tools for DNS; tests use a fake.
type Backend interface {
	// AddRoute creates the route; an error wrapping errExists means the
	// route was already in the table (not ours: it must stay).
	AddRoute(config.Route) error
	// DelRoute removes the route; a route that is already gone is not an error.
	DelRoute(config.Route) error
	// Routes reads the IPv4 routing table (Linux: all tables). An error
	// wrapping ErrNoTable means the OS does not offer it.
	Routes() ([]OSRoute, error)
	// AddRule creates a policy rule; an error wrapping errExists means an
	// identical rule is already there. Where the OS has no policy routing
	// it fails.
	AddRule(config.Rule) error
	// DelRule removes a rule; one that is already gone is not an error.
	DelRule(config.Rule) error
	// Rules reads the policy rules; nil where the OS has none.
	Rules() ([]OSRule, error)
	// AddResolver creates one per-domain DNS entry (see resolverPlan for ids).
	AddResolver(id string, servers []string) error
	// DelResolver removes an entry; one that is already gone is not an error.
	DelResolver(id string) error
	// FlushDNS drops the DNS cache, best effort.
	FlushDNS()
}

type osBackend struct{}

func (osBackend) AddRoute(r config.Route) error                 { return addRoute(r) }
func (osBackend) DelRoute(r config.Route) error                 { return delRoute(r) }
func (osBackend) Routes() ([]OSRoute, error)                    { return listRoutes() }
func (osBackend) AddRule(r config.Rule) error                   { return addRule(r) }
func (osBackend) DelRule(r config.Rule) error                   { return delRule(r) }
func (osBackend) Rules() ([]OSRule, error)                      { return listRules() }
func (osBackend) AddResolver(id string, servers []string) error { return addResolver(id, servers) }
func (osBackend) DelResolver(id string) error                   { return delResolver(id) }
func (osBackend) FlushDNS()                                     { flushDNS() }

// Store is the journal.
type Store interface {
	Load() (*config.State, []string, config.JournalStatus)
	Save(*config.State) error
}

type fileStore struct{}

func (fileStore) Load() (*config.State, []string, config.JournalStatus) {
	return config.LoadStateStatus()
}

// LoadMigrate is Load for a process that holds the lock: it also takes the
// journal of an older version over (see config.LoadStateMigrate).
func (fileStore) LoadMigrate() (*config.State, []string, config.JournalStatus) {
	return config.LoadStateMigrate()
}
func (fileStore) Save(s *config.State) error { return config.SaveState(s) }

// resolverBulkDeleter is implemented by a Backend that removes all the DNS
// entries of the journal in one go (Windows: one PowerShell call instead of one
// per zone).
type resolverBulkDeleter interface {
	DelResolvers(ids []string) error
}

// Procs tells who is running and which boot it is.
type Procs interface {
	Self() config.Owner
	Alive(config.Owner) bool
	// AliveExact: the process of that PID exists and its start time is known and equal.
	AliveExact(config.Owner) bool
	SameBoot(a, b string) bool
}

type osProcs struct{}

func (osProcs) Self() config.Owner {
	pid, start := sysproc.Self()
	return config.Owner{PID: pid, Start: start, Boot: sysproc.BootID()}
}
func (osProcs) Alive(o config.Owner) bool      { return sysproc.Alive(o.PID, o.Start) }
func (osProcs) AliveExact(o config.Owner) bool { return sysproc.AliveExact(o.PID, o.Start) }
func (osProcs) SameBoot(a, b string) bool      { return sysproc.SameBoot(a, b) }

// LockFunc takes the exclusive lock held for as long as the owner lives; it
// fails with an error wrapping config.ErrLocked if somebody holds it.
type LockFunc func() (release func() error, err error)

func osLock() (func() error, error) {
	l, err := config.LockState()
	if err != nil {
		return nil, err
	}
	return l.Release, nil
}
