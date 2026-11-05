package tui

import (
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/router"
	"github.com/UniQlow17/vpnsplit/internal/termsize"
)

// The size the menu wants grows once the first status brings warnings and
// findings; the window is fitted once more for it, exactly once.
func TestRefitAfterFirstStatus(t *testing.T) {
	m := testModel()
	m.resize = true
	before := m.wantSize()
	var fitted []termsize.Size
	m.refit = func(s termsize.Size) { fitted = append(fitted, s) }

	diags := []router.Diag{{Code: "PROXY_ON", Level: router.DiagWarn, TextRU: "прокси", TextEN: "proxy"}}
	next, cmd := m.Update(statusMsg{cfg: m.cfg, st: &config.State{}, warns: []string{"предупреждение раз", "предупреждение два"}, diags: diags})
	m = next.(model)
	after := m.wantSize()
	if after.Rows <= before.Rows {
		t.Fatalf("the filled-in menu must want more rows: %v -> %v", before, after)
	}
	if cmd == nil {
		t.Fatal("no refit")
	}
	cmd()
	if len(fitted) != 1 || fitted[0] != after {
		t.Fatalf("fitted %v, want once with %v", fitted, after)
	}
	_, cmd = m.Update(statusMsg{cfg: m.cfg, st: &config.State{}, diags: diags})
	if cmd != nil {
		t.Error("the window is fitted once more only once")
	}
}

func TestWindowRestoreKeepsTheFirst(t *testing.T) {
	var w windowRestore
	var calls []string
	w.set(func() { calls = append(calls, "first") })
	w.set(func() { calls = append(calls, "second") })
	w.do()
	w.do()
	if strings.Join(calls, ",") != "first" {
		t.Errorf("calls = %v", calls)
	}
	w.set(func() { calls = append(calls, "late") }) // finished after the end: undone at once
	if strings.Join(calls, ",") != "first,late" {
		t.Errorf("calls = %v", calls)
	}
}

// A quiet automatic apply is running: the switch must not start another operation.
func TestToggleSplitWhileBusy(t *testing.T) {
	m := testModel()
	m.admin, m.on = true, true
	m.busy, m.quiet = "Применяю маршруты", true
	m.mgr = router.NewManager()
	m.readOnly = ""
	cmd := m.toggleSplit()
	if cmd != nil || !m.on || !strings.Contains(m.flash, "Подождите") {
		t.Errorf("cmd %v on %v flash %q", cmd, m.on, m.flash)
	}
}

// An answer to an older request for the full comparison is dropped; [r] starts
// a new reading and clears the old result.
func TestDiffRequestsAreNumbered(t *testing.T) {
	m := testModel()
	m.admin = true
	m.sc = scDiag
	first := m.diffCmd()
	if first == nil || !m.diffReading || m.diffSeq != 1 {
		t.Fatalf("seq %d reading %v", m.diffSeq, m.diffReading)
	}
	old := diffMsg{b: router.Baseline{Note: "old"}, seq: 1}
	m.fullDiff = &router.Baseline{Note: "shown"}
	_ = m.diffCmd() // [r]
	if m.fullDiff != nil || m.diffSeq != 2 {
		t.Fatal("r must clear the result and number a new request")
	}
	next, _ := m.Update(old)
	m = next.(model)
	if m.fullDiff != nil || !m.diffReading {
		t.Error("a stale answer was taken")
	}
	next, _ = m.Update(diffMsg{b: router.Baseline{Note: "new"}, seq: 2, busy: true})
	m = next.(model)
	if m.fullDiff == nil || m.fullDiff.Note != "new" || m.diffReading || !m.diffPartial {
		t.Errorf("%+v reading %v partial %v", m.fullDiff, m.diffReading, m.diffPartial)
	}
}
