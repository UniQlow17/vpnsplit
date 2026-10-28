package config

// The journal of routes owned by vpnsplit is read and executed with
// administrator rights, so it must not live where an ordinary user can edit
// it. It is kept in a system directory that only the administrator can write:
//
//	Windows  %ProgramData%\vpnsplit (DACL: SYSTEM and Administrators only)
//	Linux    /var/lib/vpnsplit      (0700 root)
//	macOS    /Library/Application Support/vpnsplit (0700 root)
//
// secureStateDir (paths_<os>.go) returns the directory after checking that
// it really is protected, and refuses a directory somebody else controls.

// StateDir returns the protected directory of the journal. Without create it
// only checks an existing directory; the error satisfies os.IsNotExist when
// there is none. Creating needs administrator rights.
func StateDir(create bool) (string, error) { return secureStateDir(create) }
