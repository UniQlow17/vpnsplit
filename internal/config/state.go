package config

// Route is one route added by this tool.
type Route struct {
	Dest    string `json:"dest"` // CIDR
	Iface   string `json:"iface"`
	Gateway string `json:"gateway,omitempty"`
}

// State is the journal of routes we own. It is written BEFORE routes are
// added, so a reset can always undo them, even after a crash.
type State struct {
	Routes []Route `json:"routes"`
}

// LoadState returns the journal; a missing or broken file means "empty".
func LoadState() *State {
	s := &State{}
	_ = load("state.json", s)
	return s
}

// SaveState writes the journal atomically.
func SaveState(s *State) error { return save("state.json", s) }
