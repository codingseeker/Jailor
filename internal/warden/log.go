package warden

import (
	"fmt"
	"io"
	"os"
	"sync"

	"jailor/internal/ledger"
)

type Logger struct {
	debugMode bool
	out       io.Writer
	le        *ledger.Ledger
	mu        sync.Mutex
}

func newLogger(debug bool, out io.Writer, le *ledger.Ledger) *Logger {
	if out == nil {
		out = os.Stderr
	}
	return &Logger{debugMode: debug, out: out, le: le}
}

func (l *Logger) event(level ledger.Level, event, jailID, msg string, fields map[string]any) {
	if l == nil {
		return
	}
	if l.le != nil {
		_ = l.le.AppendLog(jailID, ledger.Log{
			Level:   level,
			Event:   event,
			JailID:  jailID,
			Message: msg,
			Fields:  fields,
		})
	}
	if l.debugMode {
		l.mu.Lock()
		defer l.mu.Unlock()
		id := jailID
		if id != "" {
			id = ledger.Short(id)
		}
		kv := ""
		for k, v := range fields {
			kv += fmt.Sprintf(" %s=%v", k, v)
		}
		fmt.Fprintf(l.out, "warden[%s] %s: %s%s\n", id, event, msg, kv)
	}
}

func (l *Logger) info(event, jailID, msg string, fields map[string]any) {
	l.event(ledger.LevelInfo, event, jailID, msg, fields)
}

func (l *Logger) debug(event, jailID, msg string, fields map[string]any) {
	l.event(ledger.LevelDebug, event, jailID, msg, fields)
}

func (l *Logger) err(event, jailID, msg string, fields map[string]any) {
	l.event(ledger.LevelError, event, jailID, msg, fields)
}
