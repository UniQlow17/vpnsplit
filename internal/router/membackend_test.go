package router

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// memBackend is an OS with a routing table and policy rules in memory. Unlike
// fakeBackend it answers Routes and Rules from what was added, so that the
// reconciler can be tested against a "real" table. It behaves like the Linux
// kernel: one route per destination, table and metric.
type memBackend struct {
	mu     sync.Mutex
	routes []OSRoute
	rules  []OSRule
	log    []string

	adds, dels, replaces, ruleAdds, ruleDels int
	onAdd                                    func(n int, r config.Route) error // called before the n-th AddRoute (1-based)
	failAdd                                  map[string]error
	failDel                                  map[string]error
	idx                                      map[string]int // adapter name -> index
	missingRes                               []string       // DNS entries that MissingResolvers reports
	routesErr                                error          // Routes fails with it
	routesBlock                              chan struct{}  // when set, Routes waits for it to be closed
	resolvers                                []OSResolver   // what ListResolvers reports
	dnsLog                                   []string       // "add <id>" and "del <id>" of the DNS entries
	resolverLists                            int            // calls of ListResolvers
	routeReads                               int            // calls of Routes
	onRoutes                                 func(n int)    // called at the start of the n-th Routes call
}

func newMemBackend() *memBackend {
	return &memBackend{idx: map[string]int{"wgcorp": 5, "wghome": 6, "eth0": 2}, failAdd: map[string]error{}, failDel: map[string]error{}}
}

func (b *memBackend) rec(s string) { b.log = append(b.log, s) }

func (b *memBackend) toOS(r config.Route) OSRoute {
	p, _ := netip.ParsePrefix(r.Dest)
	o := OSRoute{Dest: p.Masked(), Iface: r.Iface, IfIndex: b.idx[r.Iface], Gateway: addrOrZero(r.Gateway), Metric: r.EffMetric(), Table: r.Table, Ours: !r.Legacy()}
	if runtime.GOOS == "windows" { // what CreateIpForwardEntry2 gives
		o.Proto, o.Origin = mibNetMgmt, 0
	} else if o.Ours {
		o.Proto = routeProto
	}
	return o
}

func (b *memBackend) AddRoute(r config.Route) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.addLocked(r)
}

func (b *memBackend) addLocked(r config.Route) error {
	b.adds++
	if b.onAdd != nil {
		if err := b.onAdd(b.adds, r); err != nil {
			return err
		}
	}
	if err := b.failAdd[r.Dest]; err != nil {
		return err
	}
	o := b.toOS(r)
	for _, x := range b.routes {
		if x.Table == o.Table && x.Dest == o.Dest && x.Metric == o.Metric { // the kernel: one route per prefix, table and metric
			return fmt.Errorf("%w: test", errExists)
		}
	}
	b.rec("add " + r.Dest)
	b.routes = append(b.routes, o)
	return nil
}

func (b *memBackend) delLocked(r config.Route) error {
	b.dels++
	if err := b.failDel[r.Dest]; err != nil {
		return err
	}
	k := keyOf(r)
	for i, x := range b.routes {
		if x.key() == k && (!routesTagged || r.Legacy() || x.Ours) && !x.NotOurs {
			b.rec("del " + r.Dest)
			b.routes = append(b.routes[:i], b.routes[i+1:]...)
			return nil
		}
	}
	return nil
}

func (b *memBackend) DelRoute(r config.Route) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.delLocked(r)
}

// ReplaceRoute is NLM_F_REPLACE: the route with the same destination, table
// and metric is replaced, if it is ours.
func (b *memBackend) ReplaceRoute(old, next config.Route) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.replaces++
	o := b.toOS(next)
	for i, x := range b.routes {
		if x.Table == o.Table && x.Dest == o.Dest && x.Metric == o.Metric {
			if !x.Ours {
				return fmt.Errorf("%w: the route there is not ours", errExists)
			}
			if err := b.failAdd[next.Dest]; err != nil {
				return err
			}
			b.rec("replace " + next.Dest)
			b.routes[i] = o
			return nil
		}
	}
	if err := b.addLocked(next); err != nil {
		return err
	}
	return b.delLocked(old)
}

func (b *memBackend) Routes() ([]OSRoute, error) {
	if ch := b.routesBlock; ch != nil {
		<-ch
	}
	b.mu.Lock()
	b.routeReads++
	n, hook := b.routeReads, b.onRoutes
	b.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.routesErr != nil {
		return nil, b.routesErr
	}
	return append([]OSRoute(nil), b.routes...), nil
}

func (b *memBackend) ruleExists(r config.Rule) bool {
	for _, x := range b.rules {
		if k, ok := x.isOurShape(); ok && k == ruleKeyOf(r) {
			return true
		}
	}
	return false
}

func (b *memBackend) AddRule(r config.Rule) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ruleAdds++
	if b.ruleExists(r) {
		return fmt.Errorf("%w: test", errExists)
	}
	b.rec(fmt.Sprintf("addrule %d", r.Pref))
	b.rules = append(b.rules, OSRule{Pref: r.Pref, Table: r.Table, Suppress: -1, ToTable: true, Ours: true})
	return nil
}

func (b *memBackend) DelRule(r config.Rule) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ruleDels++
	for i, x := range b.rules {
		if k, ok := x.isOurShape(); ok && k == ruleKeyOf(r) {
			b.rec(fmt.Sprintf("delrule %d", r.Pref))
			b.rules = append(b.rules[:i], b.rules[i+1:]...)
			return nil
		}
	}
	return nil
}

func (b *memBackend) Rules() ([]OSRule, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]OSRule(nil), b.rules...), nil
}

func (b *memBackend) ListResolvers() ([]OSResolver, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resolverLists++
	return append([]OSResolver(nil), b.resolvers...), nil
}

func (b *memBackend) AddResolver(id string, _ []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dnsLog = append(b.dnsLog, "add "+id)
	return nil
}

func (b *memBackend) DelResolver(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dnsLog = append(b.dnsLog, "del "+id)
	return nil
}

func (b *memBackend) FlushDNS() {}

func (b *memBackend) MissingResolvers(ids []string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, id := range ids {
		for _, m := range b.missingRes {
			if m == id {
				out = append(out, id)
			}
		}
	}
	return out, nil
}

// has reports whether the main table has the route (any owner).
func (b *memBackend) has(dest, iface string) bool { return b.hasIn(0, dest, iface) }

// hasIn reports whether the table has the route (any owner).
func (b *memBackend) hasIn(table int, dest, iface string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := netip.MustParsePrefix(dest)
	for _, x := range b.routes {
		if x.Table == table && x.Dest == p && x.Iface == iface {
			return true
		}
	}
	return false
}

func (b *memBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.routes)
}

func (b *memBackend) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.adds, b.dels, b.replaces, b.ruleAdds, b.ruleDels, b.log = 0, 0, 0, 0, 0, nil
}

// plainBackend hides the optional methods of the backend inside: no
// ReplaceRoute, no MissingResolvers (what Windows and macOS have).
type plainBackend struct{ Backend }
