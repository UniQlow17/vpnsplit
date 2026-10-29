package router

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/clientcfg"
	"github.com/UniQlow17/vpnsplit/internal/config"
)

// DiagLevel is how much a finding matters.
type DiagLevel int

const (
	DiagInfo   DiagLevel = iota + 1 // good to know; nothing is wrong
	DiagWarn                        // something may not work as expected
	DiagDanger                      // the setting will not work or traffic goes where it should not
)

func (l DiagLevel) String() string {
	switch l {
	case DiagInfo:
		return "info"
	case DiagWarn:
		return "warn"
	case DiagDanger:
		return "danger"
	}
	return "?"
}

// Diag is one finding of the diagnostics: what vpnsplit saw around it that
// may break the split or change where the traffic goes. Code is stable (it is
// for tests, scripts and the documentation); the texts are for people.
type Diag struct {
	Code     string
	Level    DiagLevel
	TextRU   string
	TextEN   string
	AdviceRU string
	AdviceEN string
}

// Text is what was found, in the language asked.
func (d Diag) Text(ru bool) string {
	if ru {
		return d.TextRU
	}
	return d.TextEN
}

// Advice is what to do about it.
func (d Diag) Advice(ru bool) string {
	if ru {
		return d.AdviceRU
	}
	return d.AdviceEN
}

// Line is the finding in one line: "[warn] CODE: text. Advice".
func (d Diag) Line(ru bool) string {
	s := fmt.Sprintf("[%s] %s: %s", d.Level, d.Code, d.Text(ru))
	if a := d.Advice(ru); a != "" {
		s += " -> " + a
	}
	return s
}

// WorstDiag returns the highest level among the findings (0 for none).
func WorstDiag(list []Diag) DiagLevel {
	var w DiagLevel
	for _, d := range list {
		if d.Level > w {
			w = d.Level
		}
	}
	return w
}

// DiagSummary is the text of the indicator line: how many findings of each
// level, "" when there are none.
func DiagSummary(list []Diag, ru bool) string {
	var n [DiagDanger + 1]int
	for _, d := range list {
		if d.Level >= DiagInfo && d.Level <= DiagDanger {
			n[d.Level]++
		}
	}
	var parts []string
	add := func(l DiagLevel, en, rus string) {
		if n[l] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[l], word(ru, en, rus)))
		}
	}
	add(DiagDanger, "danger", "опасно")
	add(DiagWarn, "warnings", "предупреждений")
	add(DiagInfo, "notes", "заметок")
	return strings.Join(parts, ", ")
}

// diagnoser reads the system and judges what it found. The parts that touch
// the system are fields, so a test gives it a table, rules and a scan of its own.
// It remembers the findings for a few seconds: the TUI asks every two seconds,
// and the findings need the tables of the OS and the files of clients.
type diagnoser struct {
	routesFn func() ([]OSRoute, error)
	rulesFn  func() ([]OSRule, error)
	scanFn   func() clientcfg.Result

	mu   sync.Mutex
	key  string
	at   time.Time
	list []Diag
}

// defaultDiagnoser reads the real system.
var defaultDiagnoser = &diagnoser{
	routesFn: func() ([]OSRoute, error) { return osBackend{}.Routes() },
	rulesFn:  func() ([]OSRule, error) { return osBackend{}.Rules() },
	// the scan waits for a tool of the OS a few seconds at most (clientcfg.Cached)
	scanFn: func() clientcfg.Result { return clientcfg.Cached(clientScanAge) },
}

// diagFreshness is how long findings are reused while the key stays the same:
// the adapters and config (Sig), the default routes read each time, and the
// number of routes and rules in the journal. The rules and the other routes of
// the OS are not part of the key: a change in them is seen at the latest after
// this time.
const diagFreshness = 20 * time.Second

// clientScanAge is how old the read of the files and the registry may be.
const clientScanAge = 30 * time.Second

// Diagnose looks around and returns the findings, the most serious first. It
// only reads: the routing table and the rules of the OS, the settings of the
// clients (clientcfg), what Detect found. A part that cannot be read is
// skipped. The result is reused for diagFreshness (see there for the key); it
// is not kept when the scan of the clients did not finish.
func Diagnose(cfg *config.Config, e Env, st *config.State) []Diag {
	return defaultDiagnoser.run(cfg, e, st)
}

func (d *diagnoser) run(cfg *config.Config, e Env, st *config.State) (list []Diag) {
	if cfg == nil {
		return nil
	}
	// the findings are an extra: whatever goes wrong while looking must not stop the caller
	defer func() {
		if recover() != nil {
			list = nil
		}
	}()
	in := diagIn{goos: goos(), cfg: cfg, env: e, st: st, asNets: ripeCached}
	in.tbl, in.rs = &table{byKey: map[rkey]OSRoute{}}, &ruleSet{}
	if routes, err := d.routesFn(); err == nil {
		in.tbl = newTable(routes)
	}
	// the routes are read each time (a cheap read, the poll does it anyway): a
	// changed default route changes the findings of the full tunnels at once
	key := Sig(cfg, e) + " d=" + defaultRoutesHash(in.tbl)
	if st != nil {
		key += fmt.Sprintf(" j=%d/%d", len(st.Routes), len(st.Rules))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.key == key && time.Since(d.at) < diagFreshness {
		return d.list
	}
	if rules, err := d.rulesFn(); err == nil {
		in.rs = newRuleSet(rules)
	}
	in.cl = d.scanFn()
	list = diagnose(in)
	if in.cl.Stale {
		// the scan did not finish in time: these findings lack its part, so they are
		// not kept for diagFreshness, the next call asks again
		d.key = ""
		return list
	}
	d.key, d.at, d.list = key, time.Now(), list
	return list
}

// defaultRoutesHash is a short fingerprint of the routes of the IPv4 default
// and the halves (/0 and /1), of all tables: what the detectors of the full
// tunnels look at.
func defaultRoutesHash(t *table) string {
	if t == nil || !t.known {
		return "-"
	}
	var parts []string
	for _, r := range t.all {
		if r.Dest.Addr().Is4() && r.Dest.Bits() <= 1 {
			parts = append(parts, fmt.Sprintf("%s|%s|%s|%d|%d|%d|%v", r.Dest, r.Iface, r.Gateway, r.Metric, r.IfMetric, r.Table, r.Ours))
		}
	}
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:8])
}

// diagSort puts the most serious first; equal ones by code and text.
func diagSort(list []Diag) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Level != b.Level {
			return a.Level > b.Level
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.TextEN < b.TextEN
	})
}
