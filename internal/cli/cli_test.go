package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"jailor/internal/api"
	"jailor/internal/daemon"
	"jailor/internal/engine"
)

func runCLI(t *testing.T, ledgerDir string, args ...string) (string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	r := &Root{Out: &out, Err: &errOut}
	t.Setenv("JAILOR_LEDGER", ledgerDir)
	code := r.Run(args)
	return out.String() + errOut.String(), code
}

func TestJailCreateFromConfigAndInspect(t *testing.T) {
	dir := t.TempDir()
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	cfgPath := filepath.Join(dir, "jail.json")
	writeConfig(t, cfgPath, `{
	  "version": 1,
	  "command": ["/bin/echo", "hi"],
	  "bars": {"namespaces": ["pid","uts","mnt"]},
	  "gate": {"mode": "none"}
	}`)

	out, code := runCLI(t, ledgerDir, "jail", "create", "--config", cfgPath)
	if code != 0 {
		t.Fatalf("create code = %d, out=%s", code, out)
	}
	id := strings.TrimSpace(out)
	if id == "" {
		t.Fatal("no jail id printed")
	}

	insp, icode := runCLI(t, ledgerDir, "jail", "inspect", id)
	if icode != 0 {
		t.Fatalf("inspect code = %d, out=%s", icode, insp)
	}
	if !strings.Contains(insp, "Config Version 1") || !strings.Contains(insp, "/bin/echo") {
		t.Errorf("inspect missing persisted config: %s", insp)
	}

	logs, lcode := runCLI(t, ledgerDir, "prisoner", "logs", id)
	if lcode != 0 {
		t.Fatalf("logs code = %d, out=%s", lcode, logs)
	}
	if !strings.Contains(logs, "jail.create") {
		t.Errorf("logs missing jail.create event: %s", logs)
	}
}

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeBundle(t *testing.T, dir, configJSON string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOCICreateExportsRoundTrip(t *testing.T) {
	bundle := t.TempDir()
	writeBundle(t, bundle, `{
		"ociVersion": "1.0",
		"process": {
			"args": ["/bin/echo", "hi"],
			"env": ["A=1", "B=2"],
			"cwd": "/",
			"noNewPrivileges": true
		},
		"root": {"readonly": true},
		"hostname": "oci-jail",
		"linux": {
			"namespaces": [{"type":"pid"},{"type":"mount"},{"type":"network"}],
			"resources": {"pids": {"limit": 50}},
			"seccomp": true
		}
	}`)
	ledgerDir := filepath.Join(t.TempDir(), "ledger")

	out, code := runCLI(t, ledgerDir, "oci", "create", "--bundle", bundle, "--id", "ocirt")
	if code != 0 {
		t.Fatalf("oci create code = %d, out=%s", code, out)
	}

	exported, ecode := runCLI(t, ledgerDir, "oci", "export", "ocirt")
	if ecode != 0 {
		t.Fatalf("oci export code = %d, out=%s", ecode, exported)
	}
	for _, want := range []string{`"ociVersion": "1.0"`, `"/bin/echo"`, `"A=1"`, `"readonly"`, `"jailor"`} {
		if !strings.Contains(exported, want) {
			t.Errorf("export missing %q:\n%s", want, exported)
		}
	}
}

func startDaemon(t *testing.T) string {
	t.Helper()
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	sock := filepath.Join(ledgerDir, api.DefaultSocketName)
	eng, err := engine.New(ledgerDir)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	srv := daemon.NewServer(eng, sock)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = srv.Serve()
		close(done)
	}()
	t.Cleanup(func() {
		srv.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = eng.Shutdown(ctx)
	})
	return ledgerDir
}

func TestCLIRoutesLifecycleThroughDaemon(t *testing.T) {
	ledgerDir := startDaemon(t)

	out, code := runCLI(t, ledgerDir, "jail", "create", "/bin/echo", "hi")
	if code != 0 {
		t.Fatalf("create code = %d, out=%s", code, out)
	}
	id := strings.TrimSpace(out)
	if id == "" {
		t.Fatal("empty jail id")
	}

	out, code = runCLI(t, ledgerDir, "jail", "inspect", id)
	if code != 0 {
		t.Fatalf("inspect code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "CREATED") {
		t.Errorf("inspect missing state: %s", out)
	}

	out, code = runCLI(t, ledgerDir, "jail", "list")
	if code != 0 {
		t.Fatalf("list code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "CREATED") {
		t.Errorf("list missing jail: %s", out)
	}
	if !strings.Contains(out, "RESTARTS") || !strings.Contains(out, "FAILURES") {
		t.Errorf("list missing observability columns: %s", out)
	}

	out, code = runCLI(t, ledgerDir, "jail", "inspect", id)
	if code != 0 {
		t.Fatalf("inspect code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "Storage ") {
		t.Errorf("inspect missing storage usage: %s", out)
	}

	out, code = runCLI(t, ledgerDir, "jail", "delete", id)
	if code != 0 {
		t.Fatalf("delete code = %d, out=%s", code, out)
	}
}

func TestCLITopLevelStatsRoutedThroughDaemon(t *testing.T) {
	ledgerDir := startDaemon(t)

	out, code := runCLI(t, ledgerDir, "jail", "create", "/bin/sleep", "60")
	if code != 0 {
		t.Fatalf("create code = %d, out=%s", code, out)
	}
	id := strings.TrimSpace(out)

	out, code = runCLI(t, ledgerDir, "stats", "--ledger", ledgerDir, id)
	if code != 0 {
		t.Fatalf("top-level stats code = %d, out=%s", code, out)
	}
	for _, want := range []string{"Jail ", "State", "Memory", "CPU", "Prisoners"} {
		if !strings.Contains(out, want) {
			t.Errorf("stats missing %q: %s", want, out)
		}
	}
}

func TestCLINetworkRoutedThroughDaemon(t *testing.T) {
	ledgerDir := startDaemon(t)

	out, code := runCLI(t, ledgerDir, "network", "create", "bgnet")
	if code != 0 {
		t.Fatalf("network create code = %d, out=%s", code, out)
	}

	out, code = runCLI(t, ledgerDir, "network", "ls")
	if code != 0 {
		t.Fatalf("network ls code = %d, out=%s", code, out)
	}
	if !strings.Contains(out, "bgnet") {
		t.Errorf("network ls missing bgnet: %s", out)
	}

	out, code = runCLI(t, ledgerDir, "network", "inspect", "bgnet")
	if code != 0 {
		t.Fatalf("network inspect code = %d, out=%s", code, out)
	}

	out, code = runCLI(t, ledgerDir, "network", "rm", "bgnet")
	if code != 0 {
		t.Fatalf("network rm code = %d, out=%s", code, out)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestCLIEventsStreamsJSONOverDaemon(t *testing.T) {
	ledgerDir := startDaemon(t)

	streamed := &syncBuffer{}
	r := &Root{Out: streamed, Err: &bytes.Buffer{}}
	codeCh := make(chan int, 1)
	go func() { codeCh <- r.Run([]string{"events", "--ledger", ledgerDir}) }()

	deadline := time.Now().Add(5 * time.Second)
	created := false
	for !created && time.Now().Before(deadline) {

		out, code := runCLI(t, ledgerDir, "jail", "create", "/bin/echo", "hi")
		if code != 0 {
			t.Fatalf("create code = %d, out=%s", code, out)
		}
		if strings.Contains(streamed.String(), `"jail.created"`) {
			created = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !created {
		t.Fatalf("jail.created event was never streamed; got %q", streamed.String())
	}
	if !strings.Contains(streamed.String(), `"jailId"`) {
		t.Errorf("events stream missing jailId: %q", streamed.String())
	}

	select {
	case <-codeCh:
		t.Error("jailor events exited early while streaming")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestJailCreateCLIOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	cfgPath := filepath.Join(dir, "jail.json")
	writeConfig(t, cfgPath, `{
	  "version": 1,
	  "command": ["/bin/echo", "hi"],
	  "bars": {"namespaces": ["pid","uts","mnt"]},
	  "gate": {"mode": "none"},
	  "privileges": {"userns": "off"}
	}`)

	out, code := runCLI(t, ledgerDir, "jail", "create", "--config", cfgPath, "--userns", "on")
	if code != 0 {
		t.Fatalf("create code = %d, out=%s", code, out)
	}
	id := strings.TrimSpace(out)
	data, err := os.ReadFile(filepath.Join(ledgerDir, id, "jail.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"userns": "on"`) {
		t.Errorf("persisted record should reflect CLI override userns=on:\n%s", string(data))
	}
}

func TestPrisonerLogsUnknownJail(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	_, code := runCLI(t, ledgerDir, "prisoner", "logs", "nope")
	if code == 0 {
		t.Error("logs for unknown jail should fail")
	}
}

func TestOciCreateAndDelete(t *testing.T) {
	bundle := t.TempDir()
	writeConfig(t, filepath.Join(bundle, "config.json"), `{
	  "ociVersion": "1.0",
	  "process": {"args": ["/bin/echo", "oci"], "noNewPrivileges": true},
	  "jailor": {"network": "none", "userns": "off"}
	}`)
	ledgerDir := filepath.Join(t.TempDir(), "ledger")

	id := "my-oci-jail"
	out, code := runCLI(t, ledgerDir, "oci", "create", "--bundle", bundle, "--id", id)
	if code != 0 {
		t.Fatalf("oci create code = %d, out=%s", code, out)
	}
	if strings.TrimSpace(out) != id {
		t.Fatalf("oci create printed %q, want %q", strings.TrimSpace(out), id)
	}

	rec := filepath.Join(ledgerDir, id, "jail.json")
	data, err := os.ReadFile(rec)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if !strings.Contains(string(data), `"command": "/bin/echo"`) {
		t.Errorf("record should carry bundle command:\n%s", string(data))
	}
	del, dcode := runCLI(t, ledgerDir, "oci", "delete", id)
	if dcode != 0 {
		t.Fatalf("oci delete code = %d, out=%s", dcode, del)
	}
	if _, err := os.Stat(rec); !os.IsNotExist(err) {
		t.Errorf("record should be removed after delete, stat err=%v", err)
	}
}

func TestOciCreateMissingBundle(t *testing.T) {
	ledgerDir := filepath.Join(t.TempDir(), "ledger")
	_, code := runCLI(t, ledgerDir, "oci", "create", "--bundle", filepath.Join(t.TempDir(), "nope"))
	if code == 0 {
		t.Error("oci create with missing bundle should fail")
	}
}
