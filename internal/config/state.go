package config

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
	Resolvers []string `json:"resolvers,omitempty"` // per-domain DNS files we created
	Sig       string   `json:"sig,omitempty"`       // what was connected when applied
}

// Empty reports whether nothing is applied.
func (s *State) Empty() bool { return len(s.Routes) == 0 && len(s.Resolvers) == 0 && s.Sig == "" }

// LoadState returns the journal; a missing or broken file means "empty".
func LoadState() *State {
	s := &State{}
	_ = load("state.json", s)
	return s
}

// SaveState writes the journal atomically.
func SaveState(s *State) error { return save("state.json", s) }
