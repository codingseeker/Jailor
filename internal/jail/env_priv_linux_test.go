//go:build linux && jailor_priv

package jail

import (
	"strings"
	"testing"
)

func TestPrisonerDoesNotSeeCredentials(t *testing.T) {
	if !canUseNamespaces() {
		t.Fatal("the privileged tier cannot create namespaces")
	}
	t.Setenv("GITHUB_TOKEN", "must-not-leak")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("JAILOR_KEEP_MARK", "visible")

	out, code := runConfigured(t, &InitConfig{
		Args:      []string{testExe, "__probe", "env"},
		MountProc: false,
	}, true)
	if code != 0 {
		t.Fatalf("exit code = %d, output: %s", code, out)
	}
	for _, leaked := range []string{"must-not-leak", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK"} {
		if strings.Contains(out, leaked) {
			t.Errorf("prisoner environment leaked %q:\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, "JAILOR_KEEP_MARK=visible") {
		t.Errorf("non-credential variables must still reach the prisoner:\n%s", out)
	}
}
