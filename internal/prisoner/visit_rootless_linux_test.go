//go:build linux && jailor_rootless

package prisoner

import (
	"testing"

	"jailor/internal/jail"
)

func TestEnterFailsForStalePid(t *testing.T) {

	err := Enter(SpawnOptions{
		Pid:  99999999,
		Init: jail.InitConfig{Args: []string{"/bin/true"}},
	})
	if err == nil {
		t.Fatal("Enter of a non-existent PID should fail, not run on host")
	}
}
