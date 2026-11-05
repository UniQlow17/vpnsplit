//go:build linux

package router

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

func seamResolved(t *testing.T, idx int, cur []string) {
	t.Helper()
	old := resolverSeam
	resolverSeam.hasResolved = func() bool { return true }
	resolverSeam.ifaceByName = func(string) (int, bool, error) { return idx, true, nil }
	resolverSeam.get = func(string, string) ([]string, error) { return cur, nil }
	t.Cleanup(func() { resolverSeam = old })
}

func TestResolverPlanWithJournal(t *testing.T) {
	own := config.FormatLinuxResolver("wgcorp", 7, "", []string{"10.200.0.1"})
	zone := config.FormatLinuxResolver("wgcorp", 7, "corp.example", nil)
	journal := []string{zone, own}

	// the link has no servers: they are set
	seamResolved(t, 7, nil)
	got := resolverPlan("wgcorp", []string{"10.200.0.1"}, []string{"corp.example"}, nil)
	if !reflect.DeepEqual(got, []string{own, zone}) {
		t.Errorf("first cycle: %v", got)
	}
	// the next cycle: the link has our servers, the entry is still planned
	seamResolved(t, 7, []string{"10.200.0.1"})
	got = resolverPlan("wgcorp", []string{"10.200.0.1"}, []string{"corp.example"}, journal)
	if !reflect.DeepEqual(got, []string{own, zone}) {
		t.Errorf("second cycle: %v", got)
	}
	// the servers that are wanted changed: the entry is planned with them, not
	// with the old ones (no flip back)
	newOwn := config.FormatLinuxResolver("wgcorp", 7, "", []string{"10.200.0.9"})
	got = resolverPlan("wgcorp", []string{"10.200.0.9"}, []string{"corp.example"}, journal)
	if !reflect.DeepEqual(got, []string{newOwn, zone}) {
		t.Errorf("servers changed: %v", got)
	}
	// nothing is known about the wanted servers: the entry stays
	got = resolverPlan("wgcorp", nil, []string{"corp.example"}, journal)
	if !reflect.DeepEqual(got, []string{own, zone}) {
		t.Errorf("unknown servers: %v", got)
	}
	// somebody else's servers on the link: nothing is set
	seamResolved(t, 7, []string{"9.9.9.9"})
	got = resolverPlan("wgcorp", []string{"10.200.0.1"}, []string{"corp.example"}, journal)
	if !reflect.DeepEqual(got, []string{zone}) {
		t.Errorf("foreign servers: %v", got)
	}
	// resolved does not answer: nothing is planned
	seamResolved(t, 7, nil)
	resolverSeam.hasResolved = func() bool { return false }
	if got = resolverPlan("wgcorp", []string{"10.200.0.1"}, []string{"corp.example"}, journal); got != nil {
		t.Errorf("no resolved: %v", got)
	}
}

// physicalDNS reads resolvectl, nmcli and the resolv.conf files; with all of
// them replaced the result does not depend on the machine.
func TestPhysicalDNSIsHermetic(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(conf, []byte("nameserver 192.168.1.1\nnameserver 127.0.0.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldE, oldR, oldCmd, oldSeam := etcResolvConf, resolvedResolvConf, runCmd, resolverSeam
	t.Cleanup(func() { etcResolvConf, resolvedResolvConf, runCmd, resolverSeam = oldE, oldR, oldCmd, oldSeam })
	etcResolvConf, resolvedResolvConf = conf, filepath.Join(dir, "none")
	resolverSeam.hasResolved = func() bool { return false }
	runCmd = func(name string, args ...string) ([]byte, error) {
		switch name {
		case "nmcli":
			return nil, errors.New("no nmcli")
		case "ip": // ip -4 route get <addr>
			return []byte(args[len(args)-1] + " via 192.168.1.1 dev eth0 src 192.168.1.5\n"), nil
		}
		return nil, errors.New("unexpected " + name)
	}
	if got := physicalDNS("eth0"); !reflect.DeepEqual(got, []string{"192.168.1.1"}) {
		t.Errorf("eth0: %v", got)
	}
	if got := physicalDNS("wlan9"); len(got) != 0 {
		t.Errorf("another link: %v", got)
	}
}
