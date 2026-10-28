package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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

func (e stateEnv) load() (*State, []string, JournalStatus) {
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
				warns = append(warns, "old journal ignored: "+err.Error())
			}
			continue
		}
		old, w, err := parseState(b)
		if err != nil {
			warns = append(warns, fmt.Sprintf("old journal %s ignored: %v", p, err))
			continue
		}
		warns = append(warns, w...)
		warns = append(warns, old.trustLegacy()...)
		s.merge(old)
		migrated = append(migrated, p)
	}
	if len(migrated) > 0 && e.elevated {
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

// trustLegacy drops what an old journal, a file any process of the user could
// have written, must not be believed about. Its routes are removed with
// administrator rights, so only the kind of route this tool really adds is
// kept: not a default route (/0), which would cut the host off. Every route
// of this tool is added with metric 1, but the journal never recorded a
// metric, so that cannot be checked here; removal matches on it instead (see
// delRoute). "dns <link>" entries (Linux) are always dropped: they would
// clear the DNS servers of any link the file names.
func (s *State) trustLegacy() (warnings []string) {
	var routes []Route
	for _, r := range s.Routes {
		if p, err := ParseCIDR4(r.Dest); err != nil || strings.HasSuffix(p, "/0") {
			warnings = append(warnings, fmt.Sprintf("old journal: route %s dropped: not a route of this tool", clip(r.Dest)))
			continue
		}
		routes = append(routes, r)
	}
	s.Routes = routes
	var res []string
	for _, id := range s.Resolvers {
		if strings.HasPrefix(id, "dns ") {
			warnings = append(warnings, fmt.Sprintf("old journal: DNS entry %q dropped", clip(id)))
			continue
		}
		res = append(res, id)
	}
	s.Resolvers = res
	return warnings
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
