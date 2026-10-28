package router

import (
	"errors"
	"strings"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

type fakeOps struct {
	routes, resolvers []string
	saved             *config.State
	saveErr           error
	failRoute         string
	flushed           bool
}

func (f *fakeOps) ops() resetOps {
	return resetOps{
		delRoute: func(r config.Route) error {
			if r.Dest == f.failRoute {
				return errors.New("busy")
			}
			f.routes = append(f.routes, r.Dest)
			return nil
		},
		delResolver: func(id string) error { f.resolvers = append(f.resolvers, id); return nil },
		flushDNS:    func() { f.flushed = true },
		save:        func(s *config.State) error { f.saved = s; return f.saveErr },
	}
}

// A journal with invalid entries among valid ones: the valid ones are
// removed, the invalid ones are never passed to the OS and are reported.
func TestResetWithPartiallyInvalidJournal(t *testing.T) {
	st := &config.State{
		Routes: []config.Route{
			routeFor(""),
			{Dest: "10.0.0.0/8'; calc; '", Iface: "tun0"},
			{Dest: "172.16.0.0/12", Iface: "-D"},
		},
		Resolvers: []string{"has space", "not-a-valid-entry\n"},
	}
	var f fakeOps
	removed, errs := reset(st, f.ops())
	if removed != 1 || len(f.routes) != 1 || f.routes[0] != "10.0.0.0/8" {
		t.Errorf("removed %d, routes passed to the OS: %v", removed, f.routes)
	}
	if len(f.resolvers) != 0 {
		t.Errorf("invalid DNS entries reached the OS: %v", f.resolvers)
	}
	if len(errs) != 4 {
		t.Errorf("errors: %v", errs)
	}
	if f.saved == nil || len(f.saved.Routes) != 2 || len(f.saved.Resolvers) != 2 {
		t.Errorf("kept in the journal: %+v", f.saved)
	}
	if !f.flushed {
		t.Error("DNS cache not flushed")
	}
}

func TestResetKeepsFailedEntriesAndReportsSaveError(t *testing.T) {
	st := &config.State{Routes: []config.Route{routeFor(""), {Dest: "172.16.0.0/12", Iface: "Ethernet", Via: ViaCorp}}}
	f := fakeOps{failRoute: "172.16.0.0/12", saveErr: errors.New("disk full")}
	removed, errs := reset(st, f.ops())
	if removed != 1 || len(f.saved.Routes) != 1 || f.saved.Routes[0].Dest != "172.16.0.0/12" {
		t.Errorf("removed %d, kept %+v", removed, f.saved)
	}
	var sawSave bool
	for _, e := range errs {
		sawSave = sawSave || strings.Contains(e.Error(), "disk full")
	}
	if len(errs) != 2 || !sawSave {
		t.Errorf("the journal save error must be returned: %v", errs)
	}
}

func TestResetEmptyJournalSavesNothing(t *testing.T) {
	var f fakeOps
	if n, errs := reset(&config.State{}, f.ops()); n != 0 || len(errs) != 0 || f.saved != nil {
		t.Errorf("%d %v %+v", n, errs, f.saved)
	}
}
