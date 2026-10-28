package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// JournalStatus tells whether the protected journal could be read.
type JournalStatus int

const (
	// JournalOK: the journal was read, or there is none yet.
	JournalOK JournalStatus = iota
	// JournalDenied: the journal is for administrators only and the process
	// is not one. Its content is unknown, not empty.
	JournalDenied
	// JournalUnreadable: the journal (or its directory) exists but cannot be
	// read or is not trustworthy. It is never overwritten in this state.
	JournalUnreadable
)

// staleTmp is how old a leftover temporary file of the journal must be
// before it is removed (a younger one may belong to a running process).
const staleTmp = 10 * time.Minute

// stateEnv is where the journal lives and who is asking; tests replace it.
type stateEnv struct {
	dir      func(create bool) (string, error)
	elevated bool
	legacy   []string // directories where older versions kept the journal
}

func realStateEnv() stateEnv {
	return stateEnv{dir: StateDir, elevated: isElevated(), legacy: legacyDirs()}
}

// LoadState returns the journal; a missing or broken file means "empty".
// Entries of an old journal in the user's directory are included, see
// LoadStateChecked.
func LoadState() *State {
	s, _ := LoadStateChecked()
	return s
}

// LoadStateChecked is LoadState that also reports what was wrong: a journal
// that could not be trusted or read, and entries dropped as invalid.
func LoadStateChecked() (*State, []string) {
	s, warns, _ := LoadStateStatus()
	return s, warns
}

// LoadStateStatus is LoadStateChecked that also tells whether the protected
// journal was readable: for JournalDenied the result is "unknown", not
// "nothing applied", and for JournalUnreadable nothing may be concluded
// from it either (and it must not be saved over the journal).
//
// Older versions kept the journal in the user's config directory, where the
// user (or anything running as the user) could edit it, so that file is
// untrusted input. With administrator rights its entries are taken over once
// (see trustLegacy for which) into the protected journal and the old file is
// deleted; without, they are only included in the result. Only the legacy
// file of the account the process runs as (or sudo's user) is looked for: a
// process elevated as another administrator does not see it, and the routes
// it described are then no longer known to vpnsplit.
func LoadStateStatus() (*State, []string, JournalStatus) { return realStateEnv().load() }

func (e stateEnv) load() (*State, []string, JournalStatus) { return e.read(false) }

// LoadStateMigrate is LoadStateStatus for a process that holds the lock of the
// journal (Acquire, reset): with administrator rights it also takes the old
// journal over into the protected one and deletes it. Everywhere else
// (status, list, the polling of the TUI) the journal is only read, so that two
// processes never write it without the lock.
func LoadStateMigrate() (*State, []string, JournalStatus) { return realStateEnv().read(true) }

// read loads the journal; migrate allows writing (the transfer of old
// journals), and must be set only while the lock is held.
func (e stateEnv) read(migrate bool) (*State, []string, JournalStatus) {
	s := &State{}
	var warns []string
	status := JournalOK
	canWrite := false // the protected journal is absent or was read: it may be written

	dir, err := e.dir(false)
	switch {
	case err == nil:
		p := filepath.Join(dir, stateFile)
		b, err := readRegular(p)
		switch {
		case err == nil:
			parsed, w, perr := parseState(b)
			if perr == nil {
				s, canWrite = parsed, true
				warns = append(warns, w...)
				break
			}
			// a broken journal is set aside, not overwritten: it may be repaired by hand
			bad := p + ".bad." + time.Now().UTC().Format("20060102T150405")
			if rerr := os.Rename(p, bad); rerr != nil {
				warns = append(warns, fmt.Sprintf("journal is broken (%v) and cannot be set aside: %v", perr, rerr))
				status = JournalUnreadable
			} else {
				warns = append(warns, fmt.Sprintf("journal is broken (%v), ignored; kept as %s", perr, bad))
				canWrite = true
			}
		case os.IsNotExist(err):
			canWrite = true
		case errors.Is(err, fs.ErrPermission) && !e.elevated:
			status = JournalDenied
		default:
			warns = append(warns, "journal cannot be read: "+err.Error())
			status = JournalUnreadable
		}
		if e.elevated {
			cleanTmp(dir, stateFile)
		}
	case errors.Is(err, fs.ErrNotExist):
		canWrite = true
	case errors.Is(err, fs.ErrPermission) && !e.elevated:
		status = JournalDenied
	default:
		warns = append(warns, "journal directory is not usable: "+err.Error())
		status = JournalUnreadable
	}

	var migrated []string
	for _, d := range e.legacy {
		p := filepath.Join(d, stateFile)
		b, err := readRegular(p)
		if err != nil {
			if !os.IsNotExist(err) {
				warns = append(warns, fmt.Sprintf("old journal %s found but not transferred: %v", p, err))
			}
			continue
		}
		old, w, err := parseState(b)
		if err != nil {
			warns = append(warns, fmt.Sprintf("old journal %s found but not transferred: not a valid journal: %v", p, err))
			continue
		}
		warns = append(warns, w...)
		warns = append(warns, old.trustLegacy()...)
		s.merge(old)
		migrated = append(migrated, p)
	}
	if len(migrated) > 0 && e.elevated && migrate {
		switch {
		case !canWrite:
			warns = append(warns, "old journal not moved: the protected journal could not be read, it is left untouched")
		default:
			if err := e.save(s); err != nil {
				warns = append(warns, "old journal not moved yet: "+err.Error())
				break
			}
			for _, p := range migrated {
				// its content is in the protected journal now
				if err := removeRegular(filepath.Dir(p), filepath.Base(p)); err != nil {
					warns = append(warns, "old journal not deleted: "+err.Error())
				}
			}
		}
	}
	return s, warns, status
}

// LegacyInfo is a journal of an older version that is still in the user's
// directory: it describes routes vpnsplit put there and has not taken over yet.
type LegacyInfo struct {
	Path      string
	Routes    int
	Resolvers int
	Reason    string // why it was not transferred (English)
}

// LegacyPending lists the old-format journals that are still where older
// versions kept them, with the reason each was not transferred into the
// protected journal. It only reads.
func LegacyPending() []LegacyInfo { return realStateEnv().legacyPending() }

func (e stateEnv) legacyPending() []LegacyInfo {
	var out []LegacyInfo
	for _, d := range e.legacy {
		p := filepath.Join(d, stateFile)
		b, err := readRegular(p)
		if err != nil {
			if !os.IsNotExist(err) {
				out = append(out, LegacyInfo{Path: p, Reason: "it cannot be read: " + err.Error()})
			}
			continue
		}
		old, _, err := parseState(b)
		if err != nil {
			out = append(out, LegacyInfo{Path: p, Reason: "it is not a valid journal: " + err.Error()})
			continue
		}
		old.trustLegacy()
		li := LegacyInfo{Path: p, Routes: len(old.Routes), Resolvers: len(old.Resolvers)}
		if e.elevated {
			li.Reason = "the transfer into the protected journal did not complete (see the warnings of the start)"
		} else {
			li.Reason = "vpnsplit was not started with administrator rights, only they can move it"
		}
		out = append(out, li)
	}
	return out
}

// LegacyNote is one line about old-format journals that were found but not
// transferred, for the screen and the log; "" when there are none.
func LegacyNote(ru bool) string { return legacyNoteOf(LegacyPending(), ru) }

func legacyNoteOf(l []LegacyInfo, ru bool) string {
	var parts []string
	for _, li := range l {
		if ru {
			what := fmt.Sprintf("маршрутов: %d", li.Routes)
			if li.Resolvers > 0 {
				what += fmt.Sprintf(", DNS-записей: %d", li.Resolvers)
			}
			parts = append(parts, fmt.Sprintf("старый журнал найден, но не перенесён: %s (%s): %s", clip(li.Path), what, legacyReasonRu(li.Reason)))
			continue
		}
		what := fmt.Sprintf("%d routes", li.Routes)
		if li.Resolvers > 0 {
			what += fmt.Sprintf(", %d DNS entries", li.Resolvers)
		}
		parts = append(parts, fmt.Sprintf("old journal found but not transferred: %s (%s): %s", clip(li.Path), what, li.Reason))
	}
	if len(parts) == 0 {
		return ""
	}
	// the old journal is looked for in the profile of the account that runs vpnsplit only
	if ru {
		return strings.Join(parts, "; ") + ". Старый журнал ищется только в профиле текущей учётной записи: при запуске от имени другого администратора (UAC с другими учётными данными) он не найдётся."
	}
	return strings.Join(parts, "; ") + ". The old journal is looked for in the profile of the current account only: when started as another administrator (UAC with other credentials) it is not found."
}

func legacyReasonRu(r string) string {
	switch {
	case strings.HasPrefix(r, "vpnsplit was not started"):
		return "vpnsplit запущен без прав администратора, перенести может только он"
	case strings.HasPrefix(r, "the transfer"):
		return "перенос в защищённый журнал не завершился (см. предупреждения при запуске)"
	case strings.HasPrefix(r, "it is not a valid journal"):
		return "файл не является журналом: " + strings.TrimPrefix(r, "it is not a valid journal: ")
	case strings.HasPrefix(r, "it cannot be read"):
		return "файл не читается: " + strings.TrimPrefix(r, "it cannot be read: ")
	}
	return r
}

// trustLegacy drops what an old journal, a file any process of the user could
// have written, must not be believed about. Its routes are removed with
// administrator rights, so only what an older version could have written is
// kept: an IPv4 route of /2 or longer (a /0 would cut the host off, a /1 is how
// a VPN client takes all traffic), with no metric and no table (those versions
// recorded neither; every route of theirs had metric 1, which removal checks
// against the OS, see delRoute). Rules are dropped whole: those versions had
// none. "dns <link>" and "domain <link> <zone>" entries (Linux) are dropped too:
// they would clear the DNS servers or the domains of any link the file names. What is kept is marked FromLegacy, the
// mark is set here and nowhere else (whatever the file says about it is
// overwritten), and removal treats such routes with extra care.
func (s *State) trustLegacy() (warnings []string) {
	var routes []Route
	for _, r := range s.Routes {
		p, err := ParseCIDR4(r.Dest)
		var bits int
		if err == nil {
			if pf, perr := netip.ParsePrefix(p); perr == nil {
				bits = pf.Bits()
			} else {
				err = perr
			}
		}
		switch {
		case err != nil || bits < 2:
			warnings = append(warnings, fmt.Sprintf("old journal: route %s dropped: not a route of this tool", clip(r.Dest)))
			continue
		case r.Metric != 0 || r.Table != 0:
			warnings = append(warnings, fmt.Sprintf("old journal: route %s dropped: it has a metric or a table that old versions never wrote", clip(r.Dest)))
			continue
		}
		r.FromLegacy = true
		routes = append(routes, r)
	}
	s.Routes = routes
	if n := len(s.Rules); n > 0 {
		warnings = append(warnings, fmt.Sprintf("old journal: %d policy rules dropped: old versions had none", n))
	}
	s.Rules = nil
	var res []string
	for _, id := range s.Resolvers {
		if strings.HasPrefix(id, "dns ") || strings.HasPrefix(id, "domain ") || resolverIsRoot(id) {
			warnings = append(warnings, fmt.Sprintf("old journal: DNS entry %q dropped", clip(id)))
			continue
		}
		res = append(res, id)
	}
	s.Resolvers = res
	// the settings of the IPv6 tunnels are written back with administrator
	// rights: old versions had none, so a file that has them is not theirs
	if !s.Tun6.Empty() {
		warnings = append(warnings, "old journal: IPv6 tunnel settings dropped: old versions had none")
	}
	s.Tun6 = nil
	return warnings
}

// resolverIsRoot reports whether a DNS journal entry is about the zone "."
// (the rule that sends everything else to a DNS server): old versions never
// wrote one.
func resolverIsRoot(id string) bool {
	if id == "." {
		return true
	}
	f := strings.Fields(id)
	return len(f) == 3 && f[0] == "domain" && f[2] == "."
}

// cleanTmp removes temporary files of writeFileAtomic left behind by a crash.
func cleanTmp(dir, name string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), name+".") || !strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > staleTmp {
			_ = removeRegular(dir, e.Name()) // best effort: the next start tries again
		}
	}
}

// SaveState writes the journal atomically into the protected directory.
func SaveState(s *State) error { return stateEnv{dir: StateDir}.save(s) }

func (e stateEnv) save(s *State) error {
	dir, err := e.dir(true)
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(dir, stateFile, b, 0o600, nil)
}
