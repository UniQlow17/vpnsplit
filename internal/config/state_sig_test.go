package config

import (
	"strings"
	"testing"
)

// The Sig of the router is long (adapters, gateway, hash); the journal must
// give it back as it was, or every poll of `run` would apply again.
func TestJournalKeepsALongSig(t *testing.T) {
	sig := "corp=wgcorp#5@1a2b3c4d home=wghome#6@5e6f7a8b gw=eth0/192.168.1.1 cfg=deadbeef"
	s, _, err := parseState([]byte(`{"routes":[],"sig":"` + sig + `","dns_sig":"` + strings.Repeat("z", 300) + `"}`))
	if err != nil || s.Sig != sig || len(s.DNSSig) != 300 {
		t.Errorf("%q %d %v", s.Sig, len(s.DNSSig), err)
	}
	s, _, _ = parseState([]byte(`{"routes":[],"sig":"a\nb"}`))
	if s.Sig != "" {
		t.Error("control characters must drop the Sig")
	}
}

// Journals written before the metric (and before rules) existed.
func TestJournalOfOlderVersions(t *testing.T) {
	s, warns, err := parseState([]byte(`{"version":2,"routes":[{"dest":"10.10.0.0/16","iface":"wgcorp","via":"corp"},` +
		`{"dest":"1.2.3.4/32","iface":"eth0","gateway":"192.168.1.1","via":"pin","metric":3}]}`))
	if err != nil || len(warns) != 0 || len(s.Routes) != 2 || len(s.Rules) != 0 {
		t.Fatalf("%+v %v %v", s, warns, err)
	}
	old, newer := s.Routes[0], s.Routes[1]
	if !old.Legacy() || old.EffMetric() != 1 || newer.Legacy() || newer.EffMetric() != 3 {
		t.Errorf("%+v %+v", old, newer)
	}
	if ValidateRoute(Route{Dest: "10.0.0.0/8", Iface: "e", Metric: -1}) == nil || ValidateRoute(Route{Dest: "10.0.0.0/8", Iface: "e", Metric: 10000}) == nil {
		t.Error("absurd metrics must be rejected")
	}
	if ValidateRule(Rule{Table: OwnTable, Pref: 5000}) != nil || ValidateRule(Rule{Table: 254, Pref: 5000}) == nil ||
		ValidateRule(Rule{Table: OwnTable, Pref: 0}) == nil || ValidateRule(Rule{Table: OwnTable, Pref: 32766}) == nil {
		t.Error("rule validation")
	}
	if ValidateRoute(Route{Dest: "10.0.0.0/8", Iface: "e", Table: OwnTable}) != nil || ValidateRoute(Route{Dest: "10.0.0.0/8", Iface: "e", Table: 254}) == nil {
		t.Error("only main and our table are valid for a route")
	}
	d := &State{Rules: []Rule{{Table: 254, Pref: 5000}, {Table: OwnTable, Pref: 5000}}}
	if w := d.Sanitize(); len(w) != 1 || len(d.Rules) != 1 {
		t.Errorf("%v %+v", w, d.Rules)
	}
	if (&State{Rules: []Rule{{Table: OwnTable, Pref: 5000}}}).Empty() {
		t.Error("a journal with rules is not empty")
	}
}
