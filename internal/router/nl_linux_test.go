//go:build linux

package router

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// Read-only: the dump of routes and rules works against the real kernel and
// has what every Linux has.
func TestNetlinkDumpsOnThisMachine(t *testing.T) {
	rs, err := listRoutes()
	if err != nil {
		t.Skipf("netlink is not available here: %v", err)
	}
	var lo bool
	for _, r := range rs {
		if r.Iface == "lo" && r.Table == 0 {
			lo = true
		}
		if r.Ours && r.Table == 0 && r.Metric == ownMetric {
			t.Logf("a route of ours is in the table: %+v", r)
		}
	}
	t.Logf("%d routes, loopback in main: %v", len(rs), lo)
	rules, err := listRules()
	if err != nil {
		t.Fatal(err)
	}
	var local, mainRule bool
	for _, r := range rules {
		local = local || (r.Pref == 0 && r.Table == 255)
		mainRule = mainRule || (r.Pref == 32766 && r.Table == RuleTableMain)
	}
	if !local || !mainRule {
		t.Errorf("rules 0 (local) and 32766 (main) must be there: %+v", rules)
	}
}

func ipCmd(t *testing.T, args ...string) {
	t.Helper()
	if out, err := sysexec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// Changes the network: only inside a throw-away namespace, i.e. a container
// (the stand runs it with VPNSPLIT_NETNS_TEST=1). It exercises the netlink
// requests for real: our table, replace, and what must not be replaced.
func TestNetlinkInOwnTableAndReplace(t *testing.T) {
	if os.Getenv("VPNSPLIT_NETNS_TEST") != "1" {
		t.Skip("changes the network: set VPNSPLIT_NETNS_TEST=1 inside a container")
	}
	ipCmd(t, "link", "add", "vsd0", "type", "dummy")
	t.Cleanup(func() { _ = sysexec.Command("ip", "link", "del", "vsd0").Run() })
	ipCmd(t, "addr", "add", "10.99.0.1/24", "dev", "vsd0")
	ipCmd(t, "link", "set", "vsd0", "up")

	find := func(table int, dest string) (OSRoute, bool) {
		rs, err := listRoutes()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			if r.Table == table && r.Dest == netip.MustParsePrefix(dest) && r.Iface == "vsd0" {
				return r, true
			}
		}
		return OSRoute{}, false
	}
	old := config.Route{Dest: "10.50.0.0/16", Iface: "vsd0", Gateway: "10.99.0.2", Via: ViaCorp, Metric: ownMetric, Table: config.OwnTable}
	if err := addRoute(old); err != nil {
		t.Fatal(err)
	}
	r, ok := find(config.OwnTable, "10.50.0.0/16")
	if !ok || !r.Ours || r.Gateway != netip.MustParseAddr("10.99.0.2") || r.Metric != ownMetric {
		t.Fatalf("route in our table: %+v %v", r, ok)
	}
	if _, ok := find(0, "10.50.0.0/16"); ok {
		t.Error("the route is in the main table too")
	}
	if err := addRoute(old); !errors.Is(err, errExists) {
		t.Errorf("a second add must be EEXIST: %v", err)
	}

	// replace: the same destination, table and metric, another next hop
	next := old
	next.Gateway = "10.99.0.3"
	if err := (osBackend{}).ReplaceRoute(old, next); err != nil {
		t.Fatal(err)
	}
	r, ok = find(config.OwnTable, "10.50.0.0/16")
	if !ok || r.Gateway != netip.MustParseAddr("10.99.0.3") || !r.Ours {
		t.Errorf("after replace: %+v %v", r, ok)
	}
	n := 0
	rs, _ := listRoutes()
	for _, x := range rs {
		if x.Table == config.OwnTable && x.Dest == netip.MustParsePrefix("10.50.0.0/16") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d routes to 10.50.0.0/16 in our table", n)
	}

	// a route that is not ours is never replaced
	ipCmd(t, "route", "add", "10.51.0.0/16", "via", "10.99.0.2", "dev", "vsd0", "metric", "1", "table", "247")
	foreign := config.Route{Dest: "10.51.0.0/16", Iface: "vsd0", Gateway: "10.99.0.2", Via: ViaCorp, Metric: ownMetric, Table: config.OwnTable}
	mine := foreign
	mine.Gateway = "10.99.0.9"
	if err := (osBackend{}).ReplaceRoute(foreign, mine); !errors.Is(err, errExists) {
		t.Errorf("replacing a route that is not ours: %v", err)
	}
	if r, ok := find(config.OwnTable, "10.51.0.0/16"); !ok || r.Ours || r.Gateway != netip.MustParseAddr("10.99.0.2") {
		t.Errorf("the foreign route changed: %+v %v", r, ok)
	}
	// and delRoute leaves it alone: the tag is part of the match
	if err := delRoute(foreign); err != nil {
		t.Error(err)
	}
	if _, ok := find(config.OwnTable, "10.51.0.0/16"); !ok {
		t.Error("delRoute removed a route without our tag")
	}
	ipCmd(t, "route", "del", "10.51.0.0/16", "table", "247")

	// a replace with another metric is an add and a delete
	moved := next
	moved.Metric = ownMetric + 1
	if err := (osBackend{}).ReplaceRoute(next, moved); err != nil {
		t.Fatal(err)
	}
	if r, ok = find(config.OwnTable, "10.50.0.0/16"); !ok || r.Metric != ownMetric+1 {
		t.Errorf("after the move: %+v %v", r, ok)
	}
	if err := delRoute(moved); err != nil {
		t.Fatal(err)
	}
	if _, ok := find(config.OwnTable, "10.50.0.0/16"); ok {
		t.Error("route not removed")
	}
	if err := delRoute(moved); err != nil {
		t.Errorf("removing what is gone is no error: %v", err)
	}

	// the rule
	rule := config.Rule{Table: config.OwnTable, Pref: 5000}
	if err := addRule(rule); err != nil {
		t.Fatal(err)
	}
	if err := addRule(rule); !errors.Is(err, errExists) {
		t.Errorf("a second rule add: %v", err)
	}
	rules, err := listRules()
	if err != nil {
		t.Fatal(err)
	}
	set := newRuleSet(rules)
	if !set.has(rule) {
		t.Errorf("our rule is not found: %+v", rules)
	}
	for _, x := range rules {
		if x.Pref == 5000 && (x.Dest.IsValid() || x.hasSel() || !x.Ours) {
			t.Errorf("the rule in the kernel: %+v", x)
		}
	}
	if err := delRule(rule); err != nil {
		t.Fatal(err)
	}
	if err := delRule(rule); err != nil {
		t.Errorf("removing a rule that is gone: %v", err)
	}
}
