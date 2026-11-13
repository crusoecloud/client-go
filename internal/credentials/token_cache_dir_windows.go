//go:build windows

package credentials

import "os"

// isPrivateDir reports whether info describes a directory. Windows ACLs aren't the Unix mode-bit
// model this cache's privacy guarantees are built around (see WithDiskTokenCache's doc comment), so
// ownership and permission bits aren't checked here - only that it's actually a directory, not e.g.
// a symlink or junction standing in for one.
func isPrivateDir(info os.FileInfo) bool {
	return info.IsDir()
}
