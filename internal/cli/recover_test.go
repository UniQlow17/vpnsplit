package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/router/routertest"
)

// recover removes what a dead session left, DNS first, applies nothing and
// leaves the journal free of an owner and the lock released.
func TestRecoverRemovesWhatADeadSessionLeft(t *testing.T) {
	r := routertest.New(routertest.Journal(config.ModeSession))
	var out bytes.Buffer
	if err := recoverWith(t.Context(), r.M, &out); err != nil {
		t.Fatal(err)
	}
	if st := r.State(); !st.Empty() || st.Owner != nil {
		t.Errorf("%+v", st)
	}
	calls := r.Calls()
	if routertest.Count(calls, "route ") != 3 || routertest.Count(calls, "dns ") != 1 || routertest.Count(calls, "addroute") != 0 {
		t.Errorf("%v", calls)
	}
	if r.Held() {
		t.Error("lock not released")
	}
	if !strings.Contains(out.String(), "recovered after an earlier run") {
		t.Errorf("no report:\n%s", out.String())
	}
}

func TestRecoverWithNothingToDo(t *testing.T) {
	r := routertest.New(nil)
	var out bytes.Buffer
	if err := recoverWith(t.Context(), r.M, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nothing to recover") || len(r.Calls()) != 0 {
		t.Errorf("%s %v", out.String(), r.Calls())
	}
	if st := r.State(); st.Owner != nil {
		t.Errorf("the header of the run is left: %+v", st)
	}
	if r.Held() {
		t.Error("lock not released")
	}
}

// The routes of apply/watch are not a crashed session's: recover tells and leaves them.
func TestRecoverLeavesPersistentRoutes(t *testing.T) {
	r := routertest.New(routertest.Journal(config.ModePersistent))
	var out bytes.Buffer
	if err := recoverWith(t.Context(), r.M, &out); err != nil {
		t.Fatal(err)
	}
	if len(r.Calls()) != 0 || len(r.State().Routes) != 3 {
		t.Errorf("%v %+v", r.Calls(), r.State())
	}
	if !strings.Contains(out.String(), "left in place") || !strings.Contains(out.String(), "vpnsplit reset") {
		t.Errorf("%s", out.String())
	}
}

// What cannot be removed stays in the journal and the exit is an error.
func TestRecoverReportsWhatStays(t *testing.T) {
	r := routertest.New(routertest.Journal(config.ModeSession))
	r.Fail["10.10.0.0/16"] = errors.New("busy")
	var out bytes.Buffer
	err := recoverWith(t.Context(), r.M, &out)
	if err == nil || !strings.Contains(err.Error(), "could not be removed") {
		t.Fatalf("%v", err)
	}
	if st := r.State(); len(st.Routes) != 1 || st.Routes[0].Dest != "10.10.0.0/16" {
		t.Errorf("%+v", st)
	}
	if !strings.Contains(out.String(), "stay in the journal") {
		t.Errorf("%s", out.String())
	}
}

// A second copy is refused while the first holds the lock.
func TestRecoverRefusedWhileAnotherCopyRuns(t *testing.T) {
	r := routertest.New(nil)
	if _, _, err := r.M.Acquire(t.Context(), config.ModeSession, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := recoverWith(t.Context(), r.Second(), &bytes.Buffer{}); err == nil {
		t.Error("recover must not run next to another copy")
	}
}

func TestInstallRecoverArguments(t *testing.T) {
	if err := cmdInstallRecover([]string{"--delete"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--delete") {
		t.Errorf("a typo must not be ignored: %v", err)
	}
	if o, err := parseMenu([]string{"--no-resize"}); err != nil || !o.NoResize {
		t.Errorf("%+v %v", o, err)
	}
	if _, err := parseMenu([]string{"--nope"}); err == nil {
		t.Error("an unknown flag must be refused")
	}
}
