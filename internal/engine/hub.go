package engine

import (
	"sync"

	"jailor/internal/api"
)

type hub struct {
	mu   sync.Mutex
	subs map[chan api.Event]struct{}
	cap  int
}

func newHub(cap int) *hub {
	return &hub{subs: make(map[chan api.Event]struct{}), cap: cap}
}

func (h *hub) subscribe() chan api.Event {
	ch := make(chan api.Event, h.cap)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan api.Event) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *hub) publish(e api.Event) {
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:

		}
	}
	h.mu.Unlock()
}

func (h *hub) close() {
	h.mu.Lock()
	for ch := range h.subs {
		close(ch)
		delete(h.subs, ch)
	}
	h.mu.Unlock()
}
