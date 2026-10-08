package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"jailor/internal/api"
	"jailor/internal/engine"
)

const DialTimeout = 5 * 1e9

type Server struct {
	eng    *engine.Engine
	socket string

	ln    net.Listener
	mu    sync.Mutex
	conns map[net.Conn]struct{}

	notify func()
}

func NewServer(eng *engine.Engine, socketPath string) *Server {
	return &Server{
		eng:    eng,
		socket: socketPath,
		conns:  make(map[net.Conn]struct{}),
	}
}

func (s *Server) Engine() *engine.Engine { return s.eng }

func (s *Server) Socket() string { return s.socket }

func (s *Server) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.socket), 0o700); err != nil {
		return fmt.Errorf("daemon: create socket dir: %w", err)
	}
	if err := os.Remove(s.socket); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("daemon: remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", s.socket)
	if err != nil {
		return fmt.Errorf("daemon: listen on %s: %w", s.socket, err)
	}

	if err := os.Chmod(s.socket, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("daemon: chmod socket: %w", err)
	}
	s.ln = ln
	if s.notify != nil {
		s.notify()
	}
	return nil
}

func (s *Server) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !s.allow(conn) {
			_ = conn.Close()
			continue
		}
		s.track(conn)
		go func() {
			defer s.untrack(conn)
			s.serve(conn)
		}()
	}
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
}
func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	c.Close()
	s.mu.Unlock()
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
}

func (s *Server) allow(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var uid int
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			cerr = err
			return
		}
		uid = int(ucred.Uid)
	}); err != nil {
		return false
	}
	if cerr != nil {
		return false
	}
	if uid == 0 {
		return true
	}
	return uid == os.Geteuid()
}

func (s *Server) serve(conn net.Conn) {
	dec := json.NewDecoder(conn)
	for {
		var req api.Request
		if err := dec.Decode(&req); err != nil {
			return
		}
		if req.Version != api.Version {
			s.write(conn, api.Response{
				Version: api.Version,
				Method:  req.Method,
				OK:      false,
				Error:   api.VersionError(req.Version, api.Version),
			})
			continue
		}
		if req.Method == api.MethodEvents {

			s.streamEvents(conn)
			return
		}
		data, aerr := s.dispatch(req)
		if aerr != nil {
			s.write(conn, api.Response{Version: api.Version, Method: req.Method, OK: false, Error: aerr})
			continue
		}
		if data == nil {
			data = json.RawMessage(`{}`)
		}
		s.write(conn, api.Response{Version: api.Version, Method: req.Method, OK: true, Data: data})

		return
	}
}

func (s *Server) write(conn net.Conn, resp api.Response) {
	_ = json.NewEncoder(conn).Encode(resp)
}

func (s *Server) dispatch(req api.Request) (json.RawMessage, *api.Error) {
	switch req.Method {
	case api.MethodPing:
		return mustJSON(api.Pong{Pong: "pong"}), nil
	case api.MethodVersion:
		return mustJSON(api.VersionInfo{Version: api.Version, Name: "jailord"}), nil
	case api.MethodCreate:
		var p api.CreateParams
		if err := unmarshal(req.Params, &p); err != nil {
			return nil, api.Usage(err.Error())
		}
		rec, err := s.eng.Create(p.Jail)
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.IDResult{ID: rec.ID}), nil
	case api.MethodRun:
		var p api.RunParams
		if err := unmarshal(req.Params, &p); err != nil {
			return nil, api.Usage(err.Error())
		}
		res, err := s.eng.Run(context.Background(), p.Jail)
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(res), nil
	case api.MethodStart, api.MethodStop, api.MethodKill, api.MethodRestart, api.MethodRemove:
		id, aerr := s.idFrom(req)
		if aerr != nil {
			return nil, aerr
		}
		switch req.Method {
		case api.MethodStart:
			code, err := s.eng.Start(context.Background(), id)
			if err != nil {
				return nil, s.engErr(err)
			}
			return mustJSON(startResult{ID: id, ExitCode: code}), nil
		case api.MethodStop:
			code, err := s.eng.Stop(id)
			if err != nil {
				return nil, s.engErr(err)
			}
			return mustJSON(startResult{ID: id, ExitCode: code}), nil
		case api.MethodKill:
			code, err := s.eng.Kill(id)
			if err != nil {
				return nil, s.engErr(err)
			}
			return mustJSON(startResult{ID: id, ExitCode: code}), nil
		case api.MethodRestart:
			code, err := s.eng.Restart(context.Background(), id)
			if err != nil {
				return nil, s.engErr(err)
			}
			return mustJSON(startResult{ID: id, ExitCode: code}), nil
		default:
			if err := s.eng.Remove(id); err != nil {
				return nil, s.engErr(err)
			}
			return mustJSON(api.IDResult{ID: id}), nil
		}
	case api.MethodList:
		recs, err := s.eng.List()
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.JailList{Records: recs}), nil
	case api.MethodInspect:
		id, aerr := s.idFrom(req)
		if aerr != nil {
			return nil, aerr
		}
		rec, err := s.eng.Inspect(id)
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.JailRecord{
			Record:       *rec,
			StorageBytes: s.eng.StorageUsage(id),
		}), nil
	case api.MethodStats:
		id, aerr := s.idFrom(req)
		if aerr != nil {
			return nil, aerr
		}
		st, rec, err := s.eng.Stats(id)
		if err != nil {
			return nil, s.engErr(err)
		}
		out := api.RationsStats{ID: rec.ID, State: rec.State}
		if st != nil {
			out.MemoryCurrent = st.MemoryCurrent
			out.MemoryMax = st.MemoryMax
			out.CPUQuotaUsec = st.CPUQuotaUsec
			out.CPUPeriodUsec = st.CPUPeriodUsec
			out.CPUUsageUsec = st.CPUUsageUsec
			out.PIDsCurrent = st.PIDsCurrent
			out.PIDsMax = st.PIDsMax
		}
		return mustJSON(out), nil
	case api.MethodLogs:
		id, aerr := s.idFrom(req)
		if aerr != nil {
			return nil, aerr
		}
		logs, err := s.eng.Logs(id)
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.JailLogs{ID: id, Events: logs}), nil
	case api.MethodImageList:
		imgs, err := s.eng.Images()
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.ImageList{Images: imgs}), nil
	case api.MethodImageInspect:
		var p api.ImageParams
		if err := unmarshal(req.Params, &p); err != nil {
			return nil, api.Usage(err.Error())
		}
		img, err := s.eng.ImageInspect(p.Ref)
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(img), nil
	case api.MethodImageRemove:
		var p api.ImageParams
		if err := unmarshal(req.Params, &p); err != nil {
			return nil, api.Usage(err.Error())
		}
		n, err := s.eng.ImageRemove(p.Ref)
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.CountResult{Count: n}), nil
	case api.MethodNetworkCreate:
		var p api.NetworkParams
		if err := unmarshal(req.Params, &p); err != nil {
			return nil, api.Usage(err.Error())
		}
		n, err := s.eng.NetworkCreate(p.Name, p.Subnet, p.Gateway, p.IPv6, p.DNS)
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.NetworkResult{Network: *n}), nil
	case api.MethodNetworkList:
		nets, err := s.eng.NetworkList()
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.NetworkResult{Networks: nets}), nil
	case api.MethodNetworkInspect:
		var p api.NetworkParams
		if err := unmarshal(req.Params, &p); err != nil {
			return nil, api.Usage(err.Error())
		}
		n, allocs, err := s.eng.NetworkInspect(p.Name)
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.NetworkResult{Network: *n, Allocs: allocs}), nil
	case api.MethodNetworkRemove:
		var p api.NetworkParams
		if err := unmarshal(req.Params, &p); err != nil {
			return nil, api.Usage(err.Error())
		}
		n, err := s.eng.NetworkRemove(p.Name)
		if err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.CountResult{Count: n}), nil
	case api.MethodShutdown:
		if err := s.eng.Shutdown(context.Background()); err != nil {
			return nil, s.engErr(err)
		}
		return mustJSON(api.ShutdownOk{Stopped: true}), nil
	}
	return nil, api.Usage("unknown method " + req.Method)
}

type startResult struct {
	ID       string `json:"id"`
	ExitCode int    `json:"exitCode,omitempty"`
}

func (s *Server) streamEvents(conn net.Conn) {
	ch, unsub := s.eng.SubscribeEvents()
	defer unsub()
	enc := json.NewEncoder(conn)
	if err := enc.Encode(api.Event{
		Version: api.Version,
		Type:    api.EventSubscribed,
		Message: "event stream ready",
	}); err != nil {
		return
	}
	for ev := range ch {
		if err := enc.Encode(ev); err != nil {
			return
		}
	}
}

func (s *Server) engErr(err error) *api.Error {
	if err == nil {
		return nil
	}
	var aerr *api.Error
	if errors.As(err, &aerr) {
		return aerr
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no record for jail"), strings.Contains(msg, "not found"),
		strings.Contains(msg, "no such"):
		return api.NotFound(msg)
	case strings.Contains(msg, "is running"), strings.Contains(msg, "cannot be started"),
		strings.Contains(msg, "already"), strings.Contains(msg, "still"):
		return api.Conflict(msg)
	case strings.Contains(msg, "unavailable"), strings.Contains(msg, "not permitted"),
		strings.Contains(msg, "permission denied"):
		return api.Unavailable(msg)
	}
	return api.Internal(err)
}

func (s *Server) idFrom(req api.Request) (string, *api.Error) {
	var p api.IDParams
	if err := unmarshal(req.Params, &p); err != nil {
		return "", api.Usage("invalid params: " + err.Error())
	}
	if p.ID == "" {
		return "", api.Usage("a jail id is required")
	}
	return p.ID, nil
}

func unmarshal(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, v)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("daemon: marshal response: %v", err))
	}
	return b
}
