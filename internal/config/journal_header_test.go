package config

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestJournalHeaderRoundTrip(t *testing.T) {
	e, journal, _ := testStateEnv(t, true)
	st := &State{
		Version: JournalVersion,
		Owner:   &Owner{PID: 4242, Start: 133000000000, Boot: "boot-1"},
		Mode:    ModeSession,
		Routes:  []Route{{Dest: "10.0.0.0/8", Iface: "tun0", Via: "corp"}},
		Sig:     "x",
	}
	if err := e.save(st); err != nil {
		t.Fatal(err)
	}
	got, warns, status := e.load()
	if status != JournalOK || len(warns) != 0 {
		t.Fatalf("status %v warns %v", status, warns)
	}
	if got.Version != JournalVersion || got.Mode != ModeSession || got.Owner == nil || *got.Owner != *st.Owner {
		t.Errorf("header lost: %+v", got)
	}
	if !strings.Contains(readStr(t, journal+"/"+stateFile), `"owner"`) {
		t.Error("header not written")
	}
}

// A journal written by an older version has no header: it loads as before,
// with no owner (the entries belong to nobody who is known to be alive).
func TestJournalWithoutHeaderLoads(t *testing.T) {
	e, journal, _ := testStateEnv(t, true)
	write(t, journal, stateFile, `{"routes":[`+goodRoute+`],"sig":"s"}`)
	got, warns, status := e.load()
	if status != JournalOK || len(warns) != 0 {
		t.Fatalf("status %v warns %v", status, warns)
	}
	if got.Owner != nil || got.Mode != "" || got.Version != 0 || len(got.Routes) != 1 || got.Sig != "s" {
		t.Errorf("%+v", got)
	}
}

// An older binary reads a new journal by ignoring the header it does not know.
func TestHeaderIsIgnoredByOldFormat(t *testing.T) {
	type oldState struct {
		Routes    []Route  `json:"routes"`
		Resolvers []string `json:"resolvers,omitempty"`
		Sig       string   `json:"sig,omitempty"`
	}
	b := []byte(`{"version":2,"owner":{"pid":1},"mode":"session","routes":[` + goodRoute + `]}`)
	s, _, err := parseState(b)
	if err != nil || s.Owner == nil || s.Owner.PID != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	var o oldState
	if err := json.Unmarshal(b, &o); err != nil || len(o.Routes) != 1 {
		t.Errorf("%+v %v", o, err)
	}
}

func TestSanitizeHeader(t *testing.T) {
	s, _, err := parseState([]byte(`{"mode":"evil","owner":{"pid":-3},"routes":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode != "" || s.Owner != nil {
		t.Errorf("bad header kept: %+v", s)
	}
	s, _, _ = parseState([]byte(`{"mode":"persistent","owner":{"pid":7,"boot":"a\u0001b"}}`))
	if s.Mode != ModePersistent || s.Owner == nil || strings.ContainsRune(s.Owner.Boot, 1) {
		t.Errorf("%+v", s)
	}
}

func TestLockSecondCopy(t *testing.T) {
	dir := t.TempDir()
	first, err := lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockDir(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lock must fail with ErrLocked, got %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Errorf("second Release: %v", err)
	}
	again, err := lockDir(dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again.Release()
}
