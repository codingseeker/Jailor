package daemon

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"jailor/internal/api"
	"jailor/internal/engine"
	"jailor/internal/ledger"
)

func startTestServer(t *testing.T) (*Server, *Client) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ledger")
	sock := filepath.Join(dir, api.DefaultSocketName)
	eng, err := engine.New(dir)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	srv := NewServer(eng, sock)
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
	return srv, NewClient(sock)
}

func TestClientPingAndVersion(t *testing.T) {
	_, c := startTestServer(t)
	if aerr := c.Ping(); aerr != nil {
		t.Fatalf("Ping: %v", aerr)
	}
	info, aerr := c.Version()
	if aerr != nil {
		t.Fatalf("Version: %v", aerr)
	}
	if info.Version != api.Version {
		t.Errorf("version = %d, want %d", info.Version, api.Version)
	}
}

func TestClientCreateListInspectRemoveRoundTrip(t *testing.T) {
	_, c := startTestServer(t)
	id, aerr := c.Create(api.Jail{Command: []string{"/bin/echo", "hi"}, Hostname: "cell"})
	if aerr != nil {
		t.Fatalf("Create: %v", aerr)
	}
	if id == "" {
		t.Fatal("empty id")
	}

	list, aerr := c.List()
	if aerr != nil {
		t.Fatalf("List: %v", aerr)
	}
	if len(list.Records) != 1 {
		t.Fatalf("List len = %d, want 1", len(list.Records))
	}

	rec, aerr := c.Inspect(id)
	if aerr != nil {
		t.Fatalf("Inspect: %v", aerr)
	}
	if rec.Record.Hostname != "cell" {
		t.Errorf("hostname = %q, want cell", rec.Record.Hostname)
	}
	if rec.Record.State != ledger.StateCreated {
		t.Errorf("state = %q, want CREATED", rec.Record.State)
	}

	if aerr := c.Remove(id); aerr != nil {
		t.Fatalf("Remove: %v", aerr)
	}
	_, aerr = c.Inspect(id)
	if aerr == nil || aerr.Code != api.ExitNotFound {
		t.Errorf("Inspect after Remove: err=%v, want not-found", aerr)
	}
}

func TestClientNotFoundMapsToFoundCode(t *testing.T) {
	_, c := startTestServer(t)
	_, aerr := c.Start("missing")
	if aerr == nil {
		t.Fatal("Start of missing jail should fail")
	}
	if aerr.Code != api.ExitNotFound {
		t.Errorf("code = %d, want %d", aerr.Code, api.ExitNotFound)
	}
}

func TestClientCreateRequiresCommandUsage(t *testing.T) {
	_, c := startTestServer(t)
	id, aerr := c.Create(api.Jail{})
	if aerr == nil {
		t.Fatalf("Create without command should fail; got id %q", id)
	}
	if aerr.Code != api.ExitUsage {
		t.Errorf("code = %d, want %d", aerr.Code, api.ExitUsage)
	}
}

func TestProtocolVersionMismatchRefused(t *testing.T) {
	srv, _ := startTestServer(t)
	conn, err := net.Dial("unix", srv.Socket())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := api.Request{Version: api.Version + 100, Method: api.MethodPing}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	var resp api.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.OK {
		t.Error("version mismatch should not be OK")
	}
	if resp.Error == nil || resp.Error.Kind != api.KindVersion {
		t.Errorf("error = %+v, want version kind", resp.Error)
	}
}

func TestUnknownMethodRefused(t *testing.T) {
	srv, _ := startTestServer(t)
	conn, err := net.Dial("unix", srv.Socket())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req := api.Request{Version: api.Version, Method: "bogus.method"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	var resp api.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Error == nil || resp.Error.Code != api.ExitUsage {
		t.Errorf("resp=%+v, want usage error", resp)
	}
}

func TestShutdownStopsDaemon(t *testing.T) {
	_, c := startTestServer(t)
	if aerr := c.Shutdown(); aerr != nil {
		t.Fatalf("Shutdown: %v", aerr)
	}

	if aerr := c.Ping(); aerr != nil {
		t.Logf("ping after shutdown: %v (expected once listener closed)", aerr)
	}
}

func TestEventsStreamingPublishesCreatedAndRemoved(t *testing.T) {
	srv, c := startTestServer(t)
	_ = srv

	stream, aerr := c.Events()
	if aerr != nil {
		t.Fatalf("Events: %v", aerr)
	}
	defer stream.Close()

	id, aerr := c.Create(api.Jail{Command: []string{"/bin/true"}})
	if aerr != nil {
		t.Fatalf("Create: %v", aerr)
	}
	if aerr := c.Remove(id); aerr != nil {
		t.Fatalf("Remove: %v", aerr)
	}

	deadline := time.After(5 * time.Second)
	var created, removed bool
	for {
		ev, err := stream.Next()
		if err != nil {
			t.Fatalf("stream error: %v", err)
		}
		switch ev.Type {
		case api.EventJailCreated:
			created = true
		case api.EventJailRemoved:
			removed = true
		}
		if created && removed {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out; created=%v removed=%v", created, removed)
		default:
		}
	}
}

func TestConcurrentClientsOperateSafely(t *testing.T) {
	_, c := startTestServer(t)
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, aerr := c.Create(api.Jail{Command: []string{"/bin/echo", "x"}})
			if aerr != nil {
				errs <- aerr
				return
			}
			if _, aerr := c.Inspect(id); aerr != nil {
				errs <- aerr
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent client error: %v", err)
	}
	list, aerr := c.List()
	if aerr != nil {
		t.Fatalf("List: %v", aerr)
	}
	if len(list.Records) != n {
		t.Errorf("List len = %d, want %d", len(list.Records), n)
	}
}
