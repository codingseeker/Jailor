package api

import (
	"encoding/json"
	"fmt"
)

const Version = 1

const DefaultSocketName = "jailord.sock"

type Request struct {
	Version int             `json:"version"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Version int             `json:"version"`
	Method  string          `json:"method,omitempty"`
	OK      bool            `json:"ok"`
	Error   *Error          `json:"error,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Kind    string `json:"kind,omitempty"`
	Message string `json:"message,omitempty"`
}

func (e *Error) Error() string {
	if e == nil {
		return "api: nil error"
	}
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("api: %s (code %d)", e.Kind, e.Code)
}

const (
	ExitOK = 0

	ExitError = 1

	ExitUsage = 2

	ExitNotFound = 3

	ExitConflict = 4

	ExitUnavailable = 5

	ExitCannotExecute = 126

	ExitNotFoundCommand = 127
)

const (
	KindNotFound    = "not-found"
	KindConflict    = "conflict"
	KindUnavailable = "unavailable"
	KindUsage       = "usage"
	KindInternal    = "internal"
	KindVersion     = "version"
)

func NotFound(message string) *Error {
	return &Error{Code: ExitNotFound, Kind: KindNotFound, Message: message}
}

func Conflict(message string) *Error {
	return &Error{Code: ExitConflict, Kind: KindConflict, Message: message}
}

func Unavailable(message string) *Error {
	return &Error{Code: ExitUnavailable, Kind: KindUnavailable, Message: message}
}

func Usage(message string) *Error {
	return &Error{Code: ExitUsage, Kind: KindUsage, Message: message}
}

func Internal(err error) *Error {
	if err == nil {
		return &Error{Code: ExitError, Kind: KindInternal}
	}
	return &Error{Code: ExitError, Kind: KindInternal, Message: err.Error()}
}

func VersionError(got, want int) *Error {
	return &Error{
		Code:    ExitError,
		Kind:    KindVersion,
		Message: fmt.Sprintf("protocol version mismatch: client %d, daemon %d", got, want),
	}
}

const (
	MethodPing     = "ping"
	MethodVersion  = "version"
	MethodEvents   = "events"
	MethodShutdown = "shutdown"

	MethodCreate  = "jail.create"
	MethodRun     = "jail.run"
	MethodStart   = "jail.start"
	MethodStop    = "jail.stop"
	MethodKill    = "jail.kill"
	MethodRestart = "jail.restart"
	MethodRemove  = "jail.remove"
	MethodList    = "jail.list"
	MethodInspect = "jail.inspect"
	MethodStats   = "jail.stats"
	MethodLogs    = "jail.logs"

	MethodImageList    = "image.list"
	MethodImageInspect = "image.inspect"
	MethodImageRemove  = "image.remove"

	MethodNetworkCreate  = "network.create"
	MethodNetworkList    = "network.list"
	MethodNetworkInspect = "network.inspect"
	MethodNetworkRemove  = "network.remove"
)

type VersionInfo struct {
	Version int    `json:"version"`
	Name    string `json:"name"`
	Commit  string `json:"commit,omitempty"`
}

type Pong struct {
	Pong string `json:"pong"`
}
