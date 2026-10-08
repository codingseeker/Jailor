//go:build linux

package jail

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestPrisonerEnvironmentDropsCredentials(t *testing.T) {
	for _, name := range []string{
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"SSH_AUTH_SOCK",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"NETRC",
		"KUBECONFIG",
		"GIT_ASKPASS",
		"DOCKER_CONFIG",
	} {
		if !envBlocked(name) {
			t.Errorf("%s must never reach the prisoner environment", name)
		}
	}
}

func TestPrisonerEnvironmentDropsSecretShapedVariables(t *testing.T) {
	for _, name := range []string{
		"MY_SERVICE_TOKEN",
		"DB_PASSWORD",
		"APP_SECRET_KEY",
		"OPENAI_API_KEY",
		"SSH_PRIVATE_KEY",
		"OSS_ACCESS_KEY",
	} {
		if !envBlocked(name) {
			t.Errorf("%s must be treated as a credential", name)
		}
	}
}

func TestPrisonerEnvironmentKeepsOrdinaryVariables(t *testing.T) {
	for _, name := range []string{
		"PATH",
		"HOME",
		"USER",
		"PWD",
		"LANG",
		"TERM",
		"JAILOR_TEST_MARK",
		"GOPATH",
		"GOMAXPROCS",
		"CGO_ENABLED",
	} {
		if envBlocked(name) {
			t.Errorf("%s must not be treated as a credential", name)
		}
	}
}

func TestPrisonerEnvironmentControlsPath(t *testing.T) {
	env, err := prisonerEnvironment(&InitConfig{})
	if err != nil {
		t.Fatal(err)
	}
	path, ok := envValue(env, "PATH")
	if !ok {
		t.Fatal("PATH must always be present")
	}
	if path != strings.TrimPrefix(jailPathEnv, "PATH=") {
		t.Errorf("default PATH = %q, want the jail PATH", path)
	}
}

func TestPrisonerEnvironmentControlsIdentity(t *testing.T) {
	env, err := prisonerEnvironment(&InitConfig{Rootfs: "/srv/cell"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := envValue(env, "HOME"); got != "/" {
		t.Errorf("HOME = %q, want / for a Cell jail", got)
	}
	if got, _ := envValue(env, "USER"); got != "root" {
		t.Errorf("USER = %q, want root", got)
	}
	if got, _ := envValue(env, "PWD"); got != "/" {
		t.Errorf("PWD = %q, want /", got)
	}
	if _, ok := envValue(env, "LANG"); !ok {
		t.Error("LANG must be set")
	}
}

func TestPrisonerEnvironmentHonoursConfiguredPath(t *testing.T) {
	env, err := prisonerEnvironment(&InitConfig{
		Env: []string{"PATH=/opt/bin:/usr/bin", "JAILOR_TEST_MARK=keep"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := envValue(env, "PATH"); got != "/opt/bin:/usr/bin" {
		t.Errorf("configured PATH was replaced: %q", got)
	}
	if got, _ := envValue(env, "JAILOR_TEST_MARK"); got != "keep" {
		t.Errorf("explicit configuration was dropped: %q", got)
	}
}

func TestPrisonerEnvironmentStripsCredentialsEvenWhenExplicitlyListed(t *testing.T) {
	env, err := prisonerEnvironment(&InitConfig{
		Env: []string{"GITHUB_TOKEN=secret", "AWS_SECRET_ACCESS_KEY=secret", "SAFE=yes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"} {
		if _, ok := envValue(env, name); ok {
			t.Errorf("%s must be stripped even from an explicit environment", name)
		}
	}
	if got, _ := envValue(env, "SAFE"); got != "yes" {
		t.Errorf("SAFE = %q, want yes", got)
	}
}

func TestPrisonerEnvironmentStripsRuntimeInternals(t *testing.T) {
	env, err := prisonerEnvironment(&InitConfig{
		Env: []string{envConfigFD + "=3", envPrisonerReadFD + "=7", "KEEP=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range jailInternalEnvNames {
		if _, ok := envValue(env, name); ok {
			t.Errorf("runtime variable %s must not be visible to the prisoner", name)
		}
	}
	if got, _ := envValue(env, "KEEP"); got != "1" {
		t.Errorf("KEEP = %q, want 1", got)
	}
}

func TestJailInitEnvironmentCarriesInternals(t *testing.T) {
	t.Setenv(envConfigFD, "3")
	t.Setenv(envPrisonerReadFD, "7")
	env := jailInitEnvironment([]string{"KEEP=1"})
	if got, _ := envValue(env, envConfigFD); got != "3" {
		t.Errorf("%s missing from the jail init environment", envConfigFD)
	}
	if got, _ := envValue(env, envPrisonerReadFD); got != "7" {
		t.Errorf("%s missing from the jail init environment", envPrisonerReadFD)
	}
	if got, _ := envValue(env, "KEEP"); got != "1" {
		t.Errorf("jail init environment lost the requested variables")
	}
}

func TestPrisonerDoesNotSeeCredentials(t *testing.T) {
	if !canUseNamespaces() {
		t.Skip("environment cannot create namespaces")
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

func TestCloseInheritedDescriptorsMarksDescriptors(t *testing.T) {
	keep, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer keep.Close()
	leak, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer leak.Close()

	keepFD := int(keep.Fd())
	leakFD := int(leak.Fd())
	if err := clearCloseOnExec(keepFD); err != nil {
		t.Fatal(err)
	}
	if err := clearCloseOnExec(leakFD); err != nil {
		t.Fatal(err)
	}
	if err := closeInheritedDescriptors(map[int]bool{keepFD: true}); err != nil {
		t.Fatal(err)
	}

	if flags := fdFlags(t, keepFD); flags&fCLOEXEC != 0 {
		t.Error("kept descriptor must not be marked close-on-exec")
	}
	if fdFlags(t, leakFD)&fCLOEXEC == 0 {
		t.Error("inherited descriptor must be marked close-on-exec")
	}
}

func fdFlags(t *testing.T, fd int) uintptr {
	t.Helper()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(fGetFD), 0)
	if errno != 0 {
		t.Fatalf("F_GETFD %d: %v", fd, errno)
	}
	return flags
}
