package router

import (
	"testing"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// After we set the DNS servers on a link, the next cycle sees a link that has
// servers. If the journal has the entry (the link index and the servers match)
// the entry is still planned, or the reconciler would take it away.
func TestOwnDNSEntry(t *testing.T) {
	id := config.FormatLinuxResolver("wgcorp", 7, "", []string{"10.200.0.1", "10.200.0.2"})
	zone := config.FormatLinuxResolver("wgcorp", 7, "corp.example", nil)
	journal := []string{zone, id}

	r, ok := ownDNSEntry(journal, "wgcorp", 7, []string{"10.200.0.2", "10.200.0.1"})
	if !ok || len(r.Servers) != 2 {
		t.Fatalf("our entry is not recognised: %+v %v", r, ok)
	}
	for name, c := range map[string]struct {
		journal []string
		iface   string
		idx     int
		cur     []string
	}{
		"no servers on the link":        {journal, "wgcorp", 7, nil},
		"servers changed by somebody":   {journal, "wgcorp", 7, []string{"10.200.0.1", "9.9.9.9"}},
		"fewer servers":                 {journal, "wgcorp", 7, []string{"10.200.0.1"}},
		"the link was made again":       {journal, "wgcorp", 8, []string{"10.200.0.1", "10.200.0.2"}},
		"another link":                  {journal, "wghome", 7, []string{"10.200.0.1", "10.200.0.2"}},
		"no entry in the journal":       {[]string{zone}, "wgcorp", 7, []string{"10.200.0.1", "10.200.0.2"}},
		"an old entry without an index": {[]string{"dns wgcorp"}, "wgcorp", 7, []string{"10.200.0.1", "10.200.0.2"}},
		"garbage in the journal":        {[]string{"", "dns", "x y z", "dns wgcorp 7 not-an-address"}, "wgcorp", 7, []string{"10.200.0.1"}},
		"nil journal":                   {nil, "wgcorp", 7, []string{"10.200.0.1"}},
	} {
		if _, ok := ownDNSEntry(c.journal, c.iface, c.idx, c.cur); ok {
			t.Errorf("%s: taken for ours", name)
		}
	}
}
