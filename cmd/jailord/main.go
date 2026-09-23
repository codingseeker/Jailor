package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"jailor/internal/api"
	"jailor/internal/daemon"
	"jailor/internal/engine"
	"jailor/internal/ledger"
)

func main() {
	dir := flag.String("ledger", "", "state root (defaults to the system/ledger default)")
	socket := flag.String("socket", "", "unix socket path (default: <ledger>/jailord.sock)")
	flag.Parse()

	root := *dir
	if root == "" {
		root = ledger.DefaultDir()
	}
	sock := *socket
	if sock == "" {
		sock = filepath.Join(root, api.DefaultSocketName)
	}

	eng, err := engine.New(root)
	if err != nil {
		fatalf("engine: %v", err)
	}

	srv := daemon.NewServer(eng, sock)
	if err := srv.Listen(); err != nil {
		fatalf("%v", err)
	}
	fmt.Fprintf(os.Stderr, "jailord: listening on %s\n", srv.Socket())

	go func() {
		if err := srv.Serve(); err != nil {
			fmt.Fprintf(os.Stderr, "jailord: serve: %v\n", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "jailord: shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Shutdown(shutCtx); err != nil {
		fmt.Fprintf(os.Stderr, "jailord: shutdown: %v\n", err)
	}

	srv.Close()
	_ = os.Remove(sock)
	fmt.Fprintln(os.Stderr, "jailord: stopped")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "jailord: "+format+"\n", args...)
	os.Exit(1)
}
