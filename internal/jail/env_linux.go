//go:build linux

package jail

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

var blockedEnvNames = map[string]bool{
	"SSH_AUTH_SOCK":                          true,
	"SSH_AGENT_PID":                          true,
	"GIT_ASKPASS":                            true,
	"SSH_ASKPASS":                            true,
	"GITHUB_TOKEN":                           true,
	"GH_TOKEN":                               true,
	"GITHUB_PAT":                             true,
	"AWS_ACCESS_KEY_ID":                      true,
	"AWS_SECRET_ACCESS_KEY":                  true,
	"AWS_SESSION_TOKEN":                      true,
	"AWS_SECURITY_TOKEN":                     true,
	"AWS_PROFILE":                            true,
	"GOOGLE_APPLICATION_CREDENTIALS":         true,
	"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": true,
	"NETRC":                                  true,
	"KUBECONFIG":                             true,
	"VAULT_TOKEN":                            true,
	"NPM_TOKEN":                              true,
	"DOCKER_CONFIG":                          true,
	"GH_CONFIG_DIR":                          true,
	"GIT_CONFIG_GLOBAL":                      true,
}

var blockedEnvFragments = []string{
	"TOKEN",
	"SECRET",
	"PASSWORD",
	"PASSWD",
	"CREDENTIAL",
	"API_KEY",
	"APIKEY",
	"PRIVATE_KEY",
	"ACCESS_KEY",
	"SESSION_KEY",
}

var jailInternalEnvNames = []string{
	envInit,
	envNewPIDNS,
	envConfigFD,
	envReleaseFD,
	envReadyFD,
	envInitPIDFD,
	envPrisonerReadFD,
	envPrisonerWriteFD,
}

func envBlocked(name string) bool {
	if blockedEnvNames[name] {
		return true
	}
	upper := strings.ToUpper(name)
	for _, fragment := range blockedEnvFragments {
		if strings.Contains(upper, fragment) {
			return true
		}
	}
	return false
}

func envValue(env []string, name string) (string, bool) {
	prefix := name + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return e[len(prefix):], true
		}
	}
	return "", false
}

func prisonerEnvironment(cfg *InitConfig) ([]string, error) {
	base := os.Environ()
	if cfg.Env != nil {
		base = cfg.Env
	}
	env := make([]string, 0, len(base)+8)
	for _, entry := range base {
		name := entry
		if i := strings.IndexByte(entry, '='); i >= 0 {
			name = entry[:i]
		}
		if name == "" || envBlocked(name) {
			continue
		}
		if isJailInternalEnv(name) {
			continue
		}
		if isJailControlledEnv(name) {
			continue
		}
		env = append(env, entry)
	}

	path := jailPathEnv
	if cfg.Env != nil {
		if custom, ok := envValue(cfg.Env, "PATH"); ok && custom != "" {
			path = "PATH=" + custom
		}
	}
	env = append(env, path)

	workDir := "/"
	if cfg.WorkDir != "" {
		abs, err := filepath.Abs(cfg.WorkDir)
		if err != nil {
			return nil, fmt.Errorf("jail: work dir %q: %w", cfg.WorkDir, err)
		}
		workDir = abs
	}

	home := "/"
	if cfg.Env != nil {
		if custom, ok := envValue(cfg.Env, "HOME"); ok && custom != "" {
			home = custom
		}
	}
	env = append(env,
		"HOME="+home,
		"USER=root",
		"LOGNAME=root",
		"PWD="+workDir,
	)
	if _, ok := envValue(env, "LANG"); !ok {
		env = append(env, "LANG=C.UTF-8")
	}
	if _, ok := envValue(env, "TERM"); !ok {
		env = append(env, "TERM=dumb")
	}
	if _, ok := envValue(env, "GOMAXPROCS"); !ok {
		env = append(env, "GOMAXPROCS="+strconv.Itoa(runtime.GOMAXPROCS(0)))
	}
	return env, nil
}

var jailControlledEnvNames = []string{"PATH", "HOME", "USER", "LOGNAME", "PWD", "LANG", "TERM"}

func isJailControlledEnv(name string) bool {
	for _, controlled := range jailControlledEnvNames {
		if controlled == name {
			return true
		}
	}
	return false
}

func isJailInternalEnv(name string) bool {
	for _, internal := range jailInternalEnvNames {
		if internal == name {
			return true
		}
	}
	return false
}

func jailInitEnvironment(env []string) []string {
	initEnv := make([]string, 0, len(env)+len(jailInternalEnvNames))
	initEnv = append(initEnv, env...)
	for _, name := range jailInternalEnvNames {
		if _, ok := envValue(initEnv, name); ok {
			continue
		}
		value, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		if value == "" {
			continue
		}
		initEnv = append(initEnv, name+"="+value)
	}
	return initEnv
}

func closeInheritedDescriptors(keep map[int]bool) error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("jail: inspect inherited descriptors: %w", err)
	}
	var failures []error
	for _, entry := range entries {
		fd, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || fd < 3 || keep[fd] {
			continue
		}
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(fSetFD), uintptr(fCLOEXEC))
		switch errno {
		case 0:
		case syscall.EBADF:
			continue
		default:
			failures = append(failures, fmt.Errorf("fd %d close-on-exec: %w", fd, errno))
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return nil
}

func lookPathInJail(name, path string) (string, error) {
	if name == "" {
		return "", errors.New("jail: empty prisoner command")
	}
	if strings.ContainsRune(name, '/') {
		if err := verifyExecutable(name); err != nil {
			return "", err
		}
		return name, nil
	}
	saved := os.Getenv("PATH")
	if err := os.Setenv("PATH", path); err != nil {
		return "", fmt.Errorf("jail: resolve command: %w", err)
	}
	resolved, err := exec.LookPath(name)
	if restoreErr := os.Setenv("PATH", saved); restoreErr != nil {
		return "", fmt.Errorf("jail: restore PATH: %w", restoreErr)
	}
	if err != nil {
		return "", fmt.Errorf("jail: resolve prisoner command %q in %s: %w", name, path, err)
	}
	abs, absErr := filepath.Abs(resolved)
	if absErr != nil {
		return "", fmt.Errorf("jail: resolve prisoner command %q: %w", name, absErr)
	}
	if err := verifyExecutable(abs); err != nil {
		return "", err
	}
	return abs, nil
}

func runtimeOpenDescriptors() []int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}
	fds := make([]int, 0, len(entries))
	for _, entry := range entries {
		fd, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || fd < 3 {
			continue
		}
		fds = append(fds, fd)
	}
	sort.Ints(fds)
	return fds
}
