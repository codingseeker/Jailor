//go:build linux && jailor_rootless

package jail

import (
	"os"
	"path/filepath"
	"testing"

	"jailor/internal/cell"
)

func TestPathTraversalCellRejected(t *testing.T) {

	for _, evil := range []string{"/..", "/../../", filepath.Join(os.TempDir(), "..", "..")} {
		if err := cell.ValidateRootfsNotEscape(evil); err == nil {
			t.Errorf("path %q should be rejected as escaping the Cell", evil)
		}
	}
}

func TestCellRootIsHostRejected(t *testing.T) {
	if err := cell.ValidateRootfsNotEscape("/"); err == nil {
		t.Error("host / must be rejected as a Cell rootfs")
	}
}

func TestCellSymlinkToRootRejected(t *testing.T) {
	link := filepath.Join(t.TempDir(), "cell")
	if err := os.Symlink("/", link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := cell.ValidateRootfsNotEscape(link); err == nil {
		t.Error("symlink resolving to host / must be rejected as a Cell rootfs")
	}
}
