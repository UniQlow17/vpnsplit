package config

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

const stateFile = "state.json"

// Route is one route added by this tool.
type Route struct {
	Dest    string `json:"dest"` // CIDR
	Iface   string `json:"iface"`
	Gateway string `json:"gateway,omitempty"`
	Via     string `json:"via,omitempty"` // corp, home or direct; for display
}

// State is the journal of what we own. Each entry is written BEFORE it is
// created, so a reset can always undo it, even after a crash.
type State struct {
	Routes    []Route  `json:"routes"`
	Resolvers []string `json:"resolvers,omitempty"` // per-domain DNS entries we created
	Sig       string   `json:"sig,omitempty"`       // what was connected when applied
}

// Empty reports whether nothing is applied.
func (s *State) Empty() bool { return len(s.Routes) == 0 && len(s.Resolvers) == 0 && s.Sig == "" }

// ValidResolverEntry reports whether id is a DNS journal entry in the format
// of this OS (see resolverPlan in internal/router).
func ValidResolverEntry(id string) bool { return validResolverEntry(runtime.GOOS, id) }

func validResolverEntry(goos, id string) bool {
	switch goos {
	case "windows": // the zone
		return ValidZone(id)
	case "darwin": // /etc/resolver/<zone>
		zone := filepath.Base(id)
		return id == "/etc/resolver/"+zone && ValidZone(zone)
	default: // "dns <link>" or "domain <link> <zone>"
		f := strings.Fields(id)
		if strings.Join(f, " ") != id {
			return false
		}
		switch {
		case len(f) == 2 && f[0] == "dns":
			return ValidIface(f[1])
		case len(f) == 3 && f[0] == "domain":
			return ValidIface(f[1]) && ValidZone(f[2])
		}
		return false
	}
}

// Sanitize drops every journal entry that could not have been written by this
// tool: the journal is executed with administrator rights.
func (s *State) Sanitize() (warnings []string) {
	var routes []Route
	for _, r := range s.Routes {
		if err := ValidateRoute(r); err != nil {
			warnings = append(warnings, "journal: entry dropped: "+err.Error())
			continue
		}
		routes = append(routes, r)
	}
	s.Routes = routes
	var res []string
	for _, id := range s.Resolvers {
		if !ValidResolverEntry(id) {
			warnings = append(warnings, fmt.Sprintf("journal: DNS entry %q dropped: unexpected format", clip(id)))
			continue
		}
		res = append(res, id)
	}
	s.Resolvers = res
	if len(s.Sig) > 1024 || clip(s.Sig) != s.Sig {
		s.Sig = ""
	}
	return warnings
}

func parseState(b []byte) (*State, []string, error) {
	s := &State{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, nil, err
	}
	return s, s.Sanitize(), nil
}

// merge adds the entries of o that s does not have yet.
func (s *State) merge(o *State) {
	have := map[Route]bool{}
	for _, r := range s.Routes {
		have[r] = true
	}
	for _, r := range o.Routes {
		if !have[r] {
			s.Routes = append(s.Routes, r)
		}
	}
	for _, id := range o.Resolvers {
		s.Resolvers = AddUnique(s.Resolvers, id)
	}
	if s.Sig == "" {
		s.Sig = o.Sig
	}
}
