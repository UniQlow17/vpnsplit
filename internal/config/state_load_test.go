package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
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

	// only under the lock (read(true)) the old file is taken over
	if s, _, _ := e.load(); len(s.Routes) != 2 {
		t.Fatalf("a plain read includes the old entries: %+v", s.Routes)
	}
	if _, err := os.Lstat(lp); err != nil {
		t.Fatalf("a plain read must not delete the old file: %v", err)
	}
	if got := readStr(t, filepath.Join(journal, stateFile)); strings.Contains(got, "172.16.0.0/12") {
		t.Fatalf("a plain read must not write the journal: %s", got)
	}
	s, warns, status := e.read(true)
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

	s, warns, status := e.read(true)
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
			{Dest: "10.1.0.0/16", Iface: "e", FromLegacy: false},
			{Dest: "0.0.0.0/0", Iface: "e"},
			{Dest: "0.0.0.0/1", Iface: "e", Via: "home"},
			{Dest: "128.0.0.0/1", Iface: "e", Via: "home"},
			{Dest: "192.168.0.0/16", Iface: "e", Metric: 3},          // old versions wrote no metric
			{Dest: "192.169.0.0/16", Iface: "e", Table: 247},         // nor a table
			{Dest: "2001:db8::/32", Iface: "e"},                      // IPv4 only
			{Dest: "10.2.0.0/16", Iface: "e", Metric: 1, Table: 254}, // both
			{Dest: "172.16.0.0/12", Iface: "e", FromLegacy: true},    // the mark is set by the code, the file says nothing
		},
		Rules:     []Rule{{Table: 247, Pref: 100}},
		Resolvers: []string{"dns tun0", "domain tun0 corp.example.com", "corp.example.com"},
	}
	warns := s.trustLegacy()
	var kept []string
	for _, r := range s.Routes {
		kept = append(kept, r.Dest)
		if !r.FromLegacy {
			t.Errorf("a kept route has no mark: %+v", r)
		}
	}
	if strings.Join(kept, " ") != "10.0.0.0/8 10.1.0.0/16 172.16.0.0/12" {
		t.Errorf("kept %v", kept)
	}
	if len(s.Rules) != 0 {
		t.Errorf("rules kept: %+v", s.Rules)
	}
	if len(s.Resolvers) != 2 || len(warns) != 9 {
		t.Errorf("%+v %q", s, warns)
	}
	for _, r := range s.Resolvers {
		if strings.HasPrefix(r, "dns ") {
			t.Errorf("dns entry kept: %q", r)
		}
	}
}

// The mark FromLegacy in the old file is not read: a file that claims it for
// routes it does not have can do nothing, and the transfer sets it itself.
func TestLegacyMarkComesFromTheTransferOnly(t *testing.T) {
	e, journal, legacy := testStateEnv(t, true)
	write(t, legacy, stateFile, `{"routes":[{"dest":"0.0.0.0/1","iface":"e","from_legacy":true},{"dest":"10.0.0.0/8","iface":"e","from_legacy":false}]}`)
	s, _, _ := e.read(true)
	if len(s.Routes) != 1 || !s.Routes[0].FromLegacy {
		t.Fatalf("%+v", s.Routes)
	}
	// and it is kept in the protected journal
	if got := readStr(t, filepath.Join(journal, stateFile)); !strings.Contains(got, "from_legacy") {
		t.Errorf("%s", got)
	}
	again, _, _ := e.load()
	if len(again.Routes) != 1 || !again.Routes[0].FromLegacy {
		t.Errorf("%+v", again.Routes)
	}
}

// Without the lock (read) even an elevated process only reads.
func TestLoadElevatedButUnlockedDoesNotWrite(t *testing.T) {
	e, journal, legacy := testStateEnv(t, true)
	lp := write(t, legacy, stateFile, legacyState)
	if s, _, _ := e.load(); len(s.Routes) != 1 {
		t.Errorf("%+v", s.Routes)
	}
	if _, err := os.Lstat(lp); err != nil {
		t.Errorf("old file touched: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(journal, stateFile)); !os.IsNotExist(err) {
		t.Errorf("journal written: %v", err)
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

// realLegacyJournal has the structure of the state.json that an older version
// left in %APPDATA%\vpnsplit of a real Windows host: pretty-printed by
// json.MarshalIndent, no version or owner, no metric, an adapter name in
// Cyrillic with a space, direct routes (public 217.12.x networks) and the two
// halves of the home VPN, and a "sig" with the same adapter name in it.
const realLegacyJournal = `{
  "routes": [
    {
      "dest": "217.12.96.0/21",
      "iface": "Беспроводная сеть",
      "gateway": "192.168.1.1",
      "via": "direct"
    },
    {
      "dest": "217.12.104.0/23",
      "iface": "Беспроводная сеть",
      "gateway": "192.168.1.1",
      "via": "direct"
    },
    {
      "dest": "217.12.106.0/24",
      "iface": "Беспроводная сеть",
      "gateway": "192.168.1.1",
      "via": "direct"
    },
    {
      "dest": "0.0.0.0/1",
      "iface": "happ-xray",
      "via": "home"
    },
    {
      "dest": "128.0.0.0/1",
      "iface": "happ-xray",
      "via": "home"
    }
  ],
  "sig": "corp=- home=happ-xray gw=Беспроводная сеть/192.168.1.1 cfg=b9393d50"
}`

func utf16Of(s string, bom, bigEndian bool) []byte {
	var out []byte
	put := func(u uint16) {
		if bigEndian {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	if bom {
		put(0xFEFF)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		put(u)
	}
	return out
}

// The journal of an older version is taken over whatever way the file was
// saved: with a UTF-8 byte order mark, or as UTF-16 (PowerShell's Out-File).
func TestLegacyJournalEncodings(t *testing.T) {
	for _, c := range []struct {
		name string
		data []byte
	}{
		{"plain UTF-8", []byte(realLegacyJournal)},
		{"UTF-8 with BOM", append([]byte{0xEF, 0xBB, 0xBF}, realLegacyJournal...)},
		{"UTF-16 LE with BOM", utf16Of(realLegacyJournal, true, false)},
		{"UTF-16 BE with BOM", utf16Of(realLegacyJournal, true, true)},
		{"UTF-16 LE without BOM", utf16Of(realLegacyJournal, false, false)},
		{"UTF-16 BE without BOM", utf16Of(realLegacyJournal, false, true)},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, journal, legacy := testStateEnv(t, true)
			lp := filepath.Join(legacy, stateFile)
			if err := os.WriteFile(lp, c.data, 0o600); err != nil {
				t.Fatal(err)
			}
			s, warns, status := e.read(true)
			if status != JournalOK || len(s.Routes) != 3 || s.Routes[0].Iface != "Беспроводная сеть" || s.Sig == "" {
				t.Fatalf("%v %+v %q", status, s, warns)
			}
			for _, r := range s.Routes {
				if !r.Legacy() {
					t.Errorf("a route of the old journal has no metric: %+v", r)
				}
			}
			if _, err := os.Lstat(lp); !os.IsNotExist(err) {
				t.Errorf("the old file must be moved: %v", err)
			}
			if got := readStr(t, filepath.Join(journal, stateFile)); !strings.Contains(got, "217.12.96.0/21") {
				t.Errorf("the protected journal: %s", got)
			}
			if p := e.legacyPending(); len(p) != 0 {
				t.Errorf("nothing is pending after the transfer: %+v", p)
			}
		})
	}
}

// Without rights the old journal stays where it is, and the program says so
// and why (instead of silently showing nothing).
func TestLegacyPendingSaysWhy(t *testing.T) {
	e, _, legacy := testStateEnv(t, false)
	write(t, legacy, stateFile, realLegacyJournal)
	p := e.legacyPending()
	if len(p) != 1 || p[0].Routes != 3 || !strings.Contains(p[0].Reason, "administrator") {
		t.Fatalf("%+v", p)
	}
	ru, en := legacyNoteOf(p, true), legacyNoteOf(p, false)
	if !strings.Contains(ru, "старый журнал найден, но не перенесён") || !strings.Contains(ru, "маршрутов: 3") || !strings.Contains(ru, "без прав администратора") {
		t.Errorf("%q", ru)
	}
	if !strings.Contains(en, "found but not transferred") || !strings.Contains(en, "3 routes") {
		t.Errorf("%q", en)
	}
	if s, warns, _ := e.load(); len(s.Routes) != 3 || len(warns) != 2 {
		t.Errorf("without rights the entries are included but not moved: %+v %q", s, warns)
	}

	// a file that is not a journal: the reason is the parse error
	bad := filepath.Join(legacy, stateFile)
	if err := os.WriteFile(bad, []byte("not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	p = e.legacyPending()
	if len(p) != 1 || !strings.Contains(p[0].Reason, "not a valid journal") {
		t.Fatalf("%+v", p)
	}
	ee, _, _ := testStateEnv(t, true)
	ee.legacy = e.legacy
	_, warns, _ := ee.load()
	if !strings.Contains(strings.Join(warns, "|"), "found but not transferred") {
		t.Errorf("%q", warns)
	}

	// nothing there: no note
	if note := legacyNoteOf((&stateEnv{legacy: []string{t.TempDir()}}).legacyPending(), true); note != "" {
		t.Errorf("%q", note)
	}
}

// Old versions had neither IPv6 tunnel settings nor the zone ".": a file that
// has them is not from them, and they never reach the protected journal.
func TestLegacyDropsTun6AndRootZone(t *testing.T) {
	e, journal, legacy := testStateEnv(t, true)
	write(t, legacy, stateFile, `{"routes":[`+goodRoute+`],"resolvers":[".","domain tun0 .","domain tun0 corp.example.com","corp.example.com"],"tun6":{"teredo":"Disabled","sixtofour":"Default"}}`)
	s, warns, status := e.read(true)
	if status != JournalOK {
		t.Fatalf("status %v", status)
	}
	if s.Tun6 != nil {
		t.Errorf("Tun6 kept: %+v", s.Tun6)
	}
	for _, r := range s.Resolvers {
		if r == "." || strings.HasSuffix(r, " .") {
			t.Errorf("root zone entry kept: %q", r)
		}
	}
	if got := readStr(t, filepath.Join(journal, stateFile)); strings.Contains(got, "tun6") || strings.Contains(got, "teredo") {
		t.Errorf("Tun6 reached the journal: %s", got)
	}
	if j := strings.Join(warns, "|"); !strings.Contains(j, "IPv6 tunnel") {
		t.Errorf("no warning: %q", warns)
	}
}
