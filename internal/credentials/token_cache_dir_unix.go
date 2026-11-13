//go:build !windows

package credentials

import (
	"os"
	"syscall"
)

// isPrivateDir reports whether info describes a real directory, owned by this process' effective
// user, with no group/other permission bits set - the only state under which this process can be
// sure no other local user could have read, planted, or substituted a file inside it.
func isPrivateDir(info os.FileInfo) bool {
	if !info.IsDir() {
		return false
	}

	if info.Mode().Perm()&0o077 != 0 {
		return false
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	return int(stat.Uid) == os.Geteuid()
}
