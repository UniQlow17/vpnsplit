package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testStateEnv is a journal in a temporary directory with one legacy
// directory, as seen by an elevated (or not) process.
func testStateEnv(t *testing.T, elevated bool) (e stateEnv, journal, legacy string) {
	t.Helper()
	journal, legacy = t.TempDir(), t.TempDir()
	e = stateEnv{
		dir:      func(bool) (string, error) { return journal, nil },
		elevated: elevated,
		legacy:   []string{legacy},
	}
	return e, journal, legacy
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readStr(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	goodRoute   = `{"dest":"10.0.0.0/8","iface":"tun0","via":"corp"}`
	otherRoute  = `{"dest":"172.16.0.0/12","iface":"tun0","via":"corp"}`
	defaultRte  = `{"dest":"0.0.0.0/0","iface":"tun0"}`
	legacyState = `{"routes":[` + otherRoute + `,` + defaultRte + `]}`
)

func TestLoadMigratesLegacyIntoProtectedJournal(t *testing.T) {
	e, journal, legacy := testStateEnv(t, true)
	write(t, journal, stateFile, `{"routes":[`+goodRoute+`]}`)
	lp := write(t, legacy, stateFile, legacyState)

	s, warns, status := e.load()
	if status != JournalOK {
		t.Fatalf("status %v", status)
	}
	if len(s.Routes) != 2 {
		t.Fatalf("routes %+v (the /0 route must be dropped)", s.Routes)
	}
	if _, err := os.Lstat(lp); !os.IsNotExist(err) {
		t.Errorf("legacy file not deleted: %v", err)
	}
	if got := readStr(t, filepath.Join(journal, stateFile)); !strings.Contains(got, "172.16.0.0/12") || strings.Contains(got, "0.0.0.0/0") {
		t.Errorf("protected journal: %s", got)
	}
	if !strings.Contains(strings.Join(warns, "|"), "0.0.0.0/0") {
		t.Errorf("no warning about the dropped route: %q", warns)
	}
}

// A journal that cannot be parsed is set aside, never overwritten silently
// by the content of an untrusted legacy file.
func TestLoadBrokenProtectedJournalIsKept(t *testing.T) {
	e, journal, legacy := testStateEnv(t, true)
	const broken = `{"routes":[` + goodRoute + `` // truncated
	write(t, journal, stateFile, broken)
	write(t, legacy, stateFile, legacyState)

	s, warns, status := e.load()
	if status != JournalOK || len(s.Routes) != 1 {
		t.Fatalf("status %v state %+v", status, s)
	}
	bad, _ := filepath.Glob(filepath.Join(journal, stateFile+".bad.*"))
	if len(bad) != 1 || readStr(t, bad[0]) != broken {
		t.Fatalf("broken journal not kept: %v", bad)
	}
	if !strings.Contains(strings.Join(warns, "|"), "broken") {
		t.Errorf("no warning: %q", warns)
	}
	if got := readStr(t, filepath.Join(journal, stateFile)); !strings.Contains(got, "172.16.0.0/12") {
		t.Errorf("new journal: %s", got)
	}
}

// If the protected journal cannot be read (here: it is a directory) nothing
// is written and the legacy file stays.
func TestLoadUnreadableProtectedJournalIsNotOverwritten(t *testing.T) {
	e, journal, legacy := testStateEnv(t, true)
	if err := os.Mkdir(filepath.Join(journal, stateFile), 0o700); err != nil {
		t.Fatal(err)
	}
	lp := write(t, legacy, stateFile, legacyState)

	_, warns, status := e.load()
	if status != JournalUnreadable {
		t.Errorf("status %v", status)
	}
	if fi, err := os.Lstat(filepath.Join(journal, stateFile)); err != nil || !fi.IsDir() {
		t.Errorf("journal was replaced: %v", err)
	}
	if readStr(t, lp) != legacyState {
		t.Error("legacy file was changed")
	}
	if len(warns) == 0 {
		t.Error("no warning")
	}
}

func TestLoadWithoutRightsDoesNotMigrate(t *testing.T) {
	e, journal, legacy := testStateEnv(t, false)
	lp := write(t, legacy, stateFile, legacyState)
	s, _, _ := e.load()
	if len(s.Routes) != 1 {
		t.Errorf("legacy routes are still shown: %+v", s.Routes)
	}
	if readStr(t, lp) != legacyState {
		t.Error("legacy file changed without rights")
	}
	if _, err := os.Lstat(filepath.Join(journal, stateFile)); !os.IsNotExist(err) {
		t.Errorf("journal written without rights: %v", err)
	}
}

func TestLoadDeniedJournal(t *testing.T) {
	e := stateEnv{dir: func(bool) (string, error) { return "", fs.ErrPermission }}
	s, warns, status := e.load()
	if status != JournalDenied || !s.Empty() || len(warns) != 0 {
		t.Errorf("status %v state %+v warns %q", status, s, warns)
	}
	// the same error for an elevated process is a real problem
	e.elevated = true
	if _, _, status := e.load(); status != JournalUnreadable {
		t.Errorf("elevated status %v", status)
	}
	e.dir = func(bool) (string, error) { return "", fs.ErrNotExist }
	if _, _, status := e.load(); status != JournalOK {
		t.Errorf("no journal yet: status %v", status)
	}
}

func TestLoadDoesNotFollowLegacySymlink(t *testing.T) {
	e, _, legacy := testStateEnv(t, true)
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(legacyState), 0o600); err != nil {
		t.Fatal(err)
	}
	lp := filepath.Join(legacy, stateFile)
	if err := os.Symlink(target, lp); err != nil {
		t.Skip("cannot create symlinks here: ", err)
	}
	s, _, _ := e.load()
	if len(s.Routes) != 0 {
		t.Errorf("symlinked legacy journal was used: %+v", s.Routes)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Errorf("target was touched: %v", err)
	}
	if _, err := os.Lstat(lp); err != nil {
		t.Errorf("link was removed or followed: %v", err)
	}
}

func TestTrustLegacy(t *testing.T) {
	s := &State{
		Routes: []Route{
			{Dest: "10.0.0.0/8", Iface: "e"},
			{Dest: "0.0.0.0/0", Iface: "e"},
			{Dest: "0.0.0.0/1", Iface: "e", Via: "home"},
			{Dest: "128.0.0.0/1", Iface: "e", Via: "home"},
		},
		Resolvers: []string{"dns tun0", "domain tun0 corp.example.com", "corp.example.com"},
	}
	warns := s.trustLegacy()
	if len(s.Routes) != 3 || len(s.Resolvers) != 2 || len(warns) != 2 {
		t.Errorf("%+v %q", s, warns)
	}
	for _, r := range s.Resolvers {
		if strings.HasPrefix(r, "dns ") {
			t.Errorf("dns entry kept: %q", r)
		}
	}
}

func TestLoadCleansStaleTmp(t *testing.T) {
	e, journal, _ := testStateEnv(t, true)
	old := write(t, journal, stateFile+".1234.tmp", "x")
	fresh := write(t, journal, stateFile+".5678.tmp", "x")
	other := write(t, journal, "other.tmp", "x")
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	e.load()
	if _, err := os.Lstat(old); !os.IsNotExist(err) {
		t.Error("stale temporary file left")
	}
	for _, p := range []string{fresh, other} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
}

func TestSaveStateRoundTrip(t *testing.T) {
	e, _, _ := testStateEnv(t, true)
	want := &State{Routes: []Route{{Dest: "10.0.0.0/8", Iface: "tun0", Via: "corp"}}, Sig: "s"}
	if err := e.save(want); err != nil {
		t.Fatal(err)
	}
	got, warns, status := e.load()
	if status != JournalOK || len(warns) != 0 || len(got.Routes) != 1 || got.Sig != "s" {
		t.Errorf("%+v %q %v", got, warns, status)
	}
	e.dir = func(bool) (string, error) { return "", errors.New("boom") }
	if err := e.save(want); err == nil {
		t.Error("save error swallowed")
	}
}
