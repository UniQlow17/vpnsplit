//go:build unix

package config

import "testing"

func TestLsHasACL(t *testing.T) {
	plain := "drwxr-xr-x  5 root  wheel  160 Jan  1 00:00 /usr/local/libexec\n"
	xattr := "drwxr-xr-x@ 5 root  wheel  160 Jan  1 00:00 /usr/local/libexec\n"
	acl := "drwxr-xr-x@ 5 root  wheel  160 Jan  1 00:00 /x\n 0: group:everyone allow add_file,add_subdirectory\n"
	if lsHasACL(plain) || lsHasACL(xattr) {
		t.Error("a plain directory has no ACL")
	}
	if !lsHasACL(acl) {
		t.Error("the entries below the line mean an ACL")
	}
	if lsHasACL("") {
		t.Error("empty")
	}
}
