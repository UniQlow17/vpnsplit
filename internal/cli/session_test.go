package cli

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/router"
	"github.com/UniQlow17/vpnsplit/internal/router/routertest"
)

func TestParseReset(t *testing.T) {
	o, err := parseReset([]string{"--force", "--purge"})
	if err != nil || !o.force || !o.purge {
		t.Errorf("%+v %v", o, err)
	}
	if o, err = parseReset(nil); err != nil || o.force || o.purge {
		t.Errorf("%+v %v", o, err)
	}
	if _, err = parseReset([]string{"--forse"}); err == nil || !strings.Contains(err.Error(), "--forse") {
		t.Errorf("a typo must not be ignored: %v", err)
	}
}

func TestResetRemovesEverythingAndSaysWhatChanged(t *testing.T) {
	r := routertest.New(routertest.Journal(config.ModePersistent))
	var out bytes.Buffer
	if err := cmdReset(r.M, resetOpts{removeConfig: func() error { t.Error("config touched without --purge"); return nil }}, &out); err != nil {
		t.Fatal(err)
	}
	if st := r.State(); !st.Empty() || st.Owner != nil {
		t.Errorf("%+v", st)
	}
	if r.Held() {
		t.Error("lock not released")
	}
	for _, want := range []string{"removed 4 routes and DNS entries", "All traffic now goes straight through your ISP (past the home VPN)", "routing is back"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in:\n%s", want, out.String())
		}
	}
}

func TestResetFailureKeepsJournalAndPointsToForce(t *testing.T) {
	r := routertest.New(routertest.Journal(config.ModePersistent))
	r.Fail["10.10.0.0/16"] = errors.New("busy")
	var out bytes.Buffer
	err := cmdReset(r.M, resetOpts{}, &out)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("%v", err)
	}
	if st := r.State(); len(st.Routes) != 1 || st.Routes[0].Dest != "10.10.0.0/16" {
		t.Errorf("%+v", st)
	}
	if !strings.Contains(out.String(), "busy") {
		t.Errorf("the reason is not shown: %s", out.String())
	}
}

// After a "reboot" routes are forgotten; --force removes what the journal lists anyway.
func TestResetForceDoesNotForgetRoutesAfterReboot(t *testing.T) {
	rebooted := func() *config.State {
		j := routertest.Journal(config.ModePersistent)
		j.Owner.Boot = "boot-1"
		return j
	}
	plain := routertest.New(rebooted())
	if err := cmdReset(plain.M, resetOpts{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if n := routertest.Count(plain.Calls(), "route "); n != 0 {
		t.Errorf("routes of an earlier boot were removed without --force: %v", plain.Calls())
	}
	forced := routertest.New(rebooted())
	if err := cmdReset(forced.M, resetOpts{force: true}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if n := routertest.Count(forced.Calls(), "route "); n != 3 {
		t.Errorf("--force must try every route: %v", forced.Calls())
	}
}

// A live owner with the lock free only earns a warning: reset goes on.
func TestResetWithLivePidInJournalProceeds(t *testing.T) {
	r := routertest.New(routertest.Journal(config.ModeSession))
	r.Alive[4242] = 4000
	var out bytes.Buffer
	if err := cmdReset(r.M, resetOpts{}, &out); err != nil {
		t.Fatalf("a live PID must not block reset: %v", err)
	}
	if !strings.Contains(out.String(), "warning") || len(r.State().Routes) != 0 {
		t.Errorf("%s %+v", out.String(), r.State())
	}
}

func TestResetPurgeRemovesOnlyTheConfig(t *testing.T) {
	r := routertest.New(routertest.Journal(config.ModeSession))
	calls := 0
	var out bytes.Buffer
	err := cmdReset(r.M, resetOpts{purge: true, removeConfig: func() error { calls++; return nil }}, &out)
	if err != nil || calls != 1 || !strings.Contains(out.String(), "config deleted") {
		t.Errorf("%v calls %d: %s", err, calls, out.String())
	}
	// a config that is already gone is not an error
	r = routertest.New(nil)
	out.Reset()
	err = cmdReset(r.M, resetOpts{purge: true, removeConfig: func() error { return os.ErrNotExist }}, &out)
	if err != nil || strings.Contains(out.String(), "not deleted") {
		t.Errorf("%v: %s", err, out.String())
	}
	// a config that cannot be deleted is said, not hidden
	r = routertest.New(nil)
	out.Reset()
	_ = cmdReset(r.M, resetOpts{purge: true, removeConfig: func() error { return errors.New("access denied") }}, &out)
	if !strings.Contains(out.String(), "config not deleted: access denied") {
		t.Errorf("%s", out.String())
	}
}

// A second copy changes nothing.
func TestResetRefusedWhileAnotherCopyRuns(t *testing.T) {
	first := routertest.New(routertest.Journal(config.ModeSession))
	var out bytes.Buffer
	sess, err := acquire(t.Context(), first.M, config.ModeSession, &out)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Cleanup(time.Second)
	// the lock of the machine is taken: a copy that tries to reset is refused and changes nothing
	calls := len(first.Calls())
	var busy *router.BusyError
	if err := cmdReset(first.M, resetOpts{}, &out); !errors.As(err, &busy) {
		t.Errorf("%v", err)
	}
	if len(first.Calls()) != calls {
		t.Error("the refused copy changed something")
	}
}

func TestEndRecoversPanicAndStillCleansUp(t *testing.T) {
	r := routertest.New(nil)
	sess, err := acquire(t.Context(), r.M, config.ModeSession, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	run := func() (err error) {
		defer end(sess, func() endInfo { return endInfo{deadline: time.Now().Add(time.Second)} }, &err, &bytes.Buffer{})
		panic("boom")
	}
	err = run()
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("%v", err)
	}
	if r.Held() {
		t.Error("the lock must be released after a panic")
	}
}

func TestEndWritesTheOutcomeOfASession(t *testing.T) {
	r := routertest.New(routertest.Journal(config.ModePersistent))
	sess, err := acquire(t.Context(), r.M, config.ModeSession, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var saved []string
	var rerr error
	endWith(sess, endInfo{deadline: time.Now().Add(5 * time.Second), reason: "signal terminated",
		saveLast: func(s string) error { saved = append(saved, s); return nil }}, &rerr, &out)
	if rerr != nil || len(saved) != 1 {
		t.Fatalf("%v %q", rerr, saved)
	}
	if !strings.Contains(saved[0], "(signal terminated)") || !strings.Contains(saved[0], "removed: 3 routes, 1 DNS") || !strings.Contains(saved[0], "past the home VPN") {
		t.Errorf("%q", saved[0])
	}
	if !strings.Contains(out.String(), "All traffic now goes straight through your ISP") {
		t.Errorf("%s", out.String())
	}
}

func TestEndInPersistentModeWritesNothing(t *testing.T) {
	r := routertest.New(nil)
	sess, err := acquire(t.Context(), r.M, config.ModePersistent, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	var rerr error
	endWith(sess, endInfo{deadline: time.Now().Add(time.Second), saveLast: func(string) error { t.Error("written"); return nil }}, &rerr, &bytes.Buffer{})
}

func TestEndForWithoutSignalGivesAMinute(t *testing.T) {
	if d := time.Until(endFor(nil).deadline); d < 55*time.Second {
		t.Errorf("%v", d)
	}
}

func TestPrintOwnerWarnsAboutDNSOfDeadSession(t *testing.T) {
	const gone = 2147483000
	st := &config.State{Mode: config.ModeSession, Owner: &config.Owner{PID: gone, Start: 1},
		Routes: []config.Route{{Dest: "10.0.0.0/8", Iface: "tun0"}}, Resolvers: []string{routertest.Resolver("corp.example")}}
	var out bytes.Buffer
	printOwner(&out, st)
	if !strings.Contains(out.String(), "DNS rules of the previous session are still in place") || !strings.Contains(out.String(), "administrator rights") {
		t.Errorf("%s", out.String())
	}
	st.Resolvers = nil
	out.Reset()
	printOwner(&out, st)
	if strings.Contains(out.String(), "WARNING") {
		t.Errorf("%s", out.String())
	}
}
