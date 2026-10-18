package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

type Hub struct {
	mu               sync.Mutex
	a                *API
	auth             Authenticator
	subs             map[*eventStream]bool
	cache            [3][]byte
	keys             [3]string
	closing, started bool
	stop, done       chan struct{}
}
type eventStream struct {
	request *http.Request
	ctx     context.Context
	cancel  context.CancelFunc
	rc      *http.ResponseController
	closed  bool
	slots   [3]chan []byte
	wake    chan struct{}
}

// NewWithHub gives the server assembly ownership of the stream lifetime.
func NewWithHub(s *rules.Service, n Nodes, auth Authenticator, logger *log.Logger, opts Options) (*gin.Engine, *Hub) {
	h := &Hub{}
	opts.hub = h
	e := New(s, n, auth, logger, opts)
	return e, h
}
func (h *Hub) init(a *API, auth Authenticator) {
	h.a, h.auth, h.subs = a, auth, map[*eventStream]bool{}
	h.stop, h.done = make(chan struct{}), make(chan struct{})
}
func (h *Hub) ticks(d time.Duration) (<-chan time.Time, func()) {
	if f := h.a.systemOptions.eventsTick; f != nil {
		return f(d)
	}
	t := time.NewTicker(d)
	return t.C, t.Stop
}
func (h *Hub) run() {
	defer close(h.done)
	tick, stop := h.ticks(time.Second)
	defer stop()
	for {
		select {
		case <-h.stop:
			return
		case <-tick:
			h.round()
			if f := h.a.systemOptions.roundDone; f != nil {
				f()
			}
		}
	}
}
func (h *Hub) valid(r *http.Request) bool {
	if h.auth == nil {
		return false
	}
	a, err := h.auth(r)
	return err == nil && a.Kind == rules.UI
}
func (h *Hub) closeStream(s *eventStream) bool {
	if !h.subs[s] || s.closed {
		return false
	}
	s.closed = true
	_ = s.rc.SetWriteDeadline(time.Now())
	s.cancel()
	return true
}
func (h *Hub) remove(s *eventStream) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closeStream(s)
	delete(h.subs, s)
	if len(h.subs) == 0 {
		h.cache, h.keys = [3][]byte{}, [3]string{}
	}
}
func (h *Hub) Close() {
	h.mu.Lock()
	if !h.closing {
		h.closing = true
		close(h.stop)
		for s := range h.subs {
			h.closeStream(s)
		}
	}
	started := h.started
	h.mu.Unlock()
	if started {
		<-h.done
	}
}
func putLatest(slot chan []byte, b []byte) {
	select {
	case <-slot:
	default:
	}
	select {
	case slot <- b:
	default:
	}
}
func wakeStream(s *eventStream) {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (h *Hub) round() {
	h.mu.Lock()
	readers := []*eventStream{}
	if !h.closing {
		for s := range h.subs {
			if !s.closed {
				readers = append(readers, s)
			}
		}
	}
	h.mu.Unlock()
	for _, s := range readers {
		if !h.valid(s.request) {
			h.mu.Lock()
			h.closeStream(s)
			h.mu.Unlock()
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	active := false
	for s := range h.subs {
		active = active || !s.closed
	}
	if h.closing || !active {
		return
	}
	payload, keys, err := h.read()
	if err != nil {
		closed := 0
		for s := range h.subs {
			if h.closeStream(s) {
				closed++
			}
		}
		h.cache, h.keys = [3][]byte{}, [3]string{}
		h.a.log.Printf("hub snapshot read failed; closed_streams=%d", closed)
		return
	}
	for i, name := range []string{"rules", "nodes", "traffic"} {
		if h.cache[i] != nil && keys[i] == h.keys[i] {
			continue
		}
		h.cache[i] = []byte("event: " + name + "\ndata: " + string(payload[i]) + "\n\n")
		h.keys[i] = keys[i]
		for s := range h.subs {
			if !s.closed {
				putLatest(s.slots[i], h.cache[i])
				wakeStream(s)
			}
		}
	}
}
func (h *Hub) read() (payload [3][]byte, keys [3]string, err *Error) {
	status := h.a.nodes.Status()
	if f := h.a.systemOptions.nodesRead; f != nil {
		if err = f(); err != nil {
			return
		}
	}
	nodes, err := h.a.nodesData(status)
	if err != nil {
		return
	}
	top, key, err := h.a.trafficTopKey(5)
	if err != nil {
		return
	}
	reconcile := map[string]any{}
	overview := map[string]any{"nodes_total": len(nodes.Nodes), "nodes_online": 0}
	for _, n := range nodes.Nodes {
		if n.Online {
			overview["nodes_online"] = overview["nodes_online"].(int) + 1
		}
	}
	for _, n := range status {
		reconcile[n.Name] = gin.H{"rules": reconcileDTO(n.RuleReconcile), "whitelist": reconcileDTO(n.WhitelistReconcile)}
	}
	for field, rate := range map[string]string{"dropped_pps": "dropped_packets", "passed_pps": "passed_packets", "dropped_bytes_ps": "dropped_bytes", "passed_bytes_ps": "passed_bytes"} {
		var sum float64
		for _, n := range status {
			sum += n.Rates[rate]
		}
		overview[field] = sum
	}
	seq, gen := h.a.service.Revision()
	values := [3]any{gin.H{"seq": seq, "gen": gen}, gin.H{"epoch": nodes.Epoch, "nodes": nodes.Nodes, "reconcile": reconcile}, gin.H{"overview": overview, "top": top}}
	keys[0], keys[2] = fmt.Sprint(seq), key
	for i, value := range values {
		if i != 1 && h.cache[i] != nil && h.keys[i] == keys[i] {
			continue
		}
		var e error
		payload[i], e = json.Marshal(value)
		if e != nil {
			return payload, keys, &Error{Code: "internal"}
		}
	}
	keys[1] = string(payload[1])
	return
}
func (h *Hub) events(c *gin.Context) {
	rc := http.NewResponseController(c.Writer.(interface{ Unwrap() http.ResponseWriter }).Unwrap())
	if c.Request.ContentLength != 0 {
		_ = rc.SetReadDeadline(time.Now())
		_ = rc.SetWriteDeadline(time.Now().Add(time.Second))
		h.a.fail(c, &Error{Code: "bad_request", Message: "events request must have no body"})
		return
	}
	if f := h.a.systemOptions.atRegister; f != nil {
		f()
	}
	ctx, cancel := context.WithCancel(c.Request.Context())
	s := &eventStream{request: c.Request.Clone(context.Background()), ctx: ctx, cancel: cancel, rc: rc, wake: make(chan struct{}, 1)}
	defer cancel()
	for i := range s.slots {
		s.slots[i] = make(chan []byte, 1)
	}
	h.mu.Lock()
	closing := h.closing
	if !closing {
		cached := h.cache
		if f := h.a.systemOptions.afterSnapshotRead; f != nil {
			f()
		}
		h.subs[s] = true
		for i, b := range cached {
			if b != nil {
				putLatest(s.slots[i], b)
			}
		}
		wakeStream(s)
		if !h.started {
			h.started = true
			go h.run()
		}
	}
	h.mu.Unlock()
	if !closing {
		defer h.remove(s)
		if f := h.a.systemOptions.afterRegister; f != nil {
			f()
		}
		h.mu.Lock()
		valid := !h.closing && !s.closed && h.valid(c.Request)
		h.mu.Unlock()
		if !valid {
			return
		}
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Accel-Buffering", "no")
	if closing {
		_ = rc.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = c.Writer.Write([]byte("retry: 3000\n\n"))
		_ = rc.Flush()
		return
	}
	write := func(b []byte, authenticate bool) bool {
		if authenticate {
			if f := h.a.systemOptions.beforeWriteAuth; f != nil {
				f()
			}
		}
		h.mu.Lock()
		ok := !h.closing && !s.closed
		if ok && authenticate {
			ok = h.valid(s.request)
		}
		if ok {
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		}
		h.mu.Unlock()
		if !ok {
			return false
		}
		_, err := c.Writer.Write(b)
		return err == nil && rc.Flush() == nil
	}
	if !write([]byte("retry: 3000\n\n"), false) {
		return
	}
	beat, stop := h.ticks(15 * time.Second)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-beat:
			if !write([]byte(": ping\n\n"), true) {
				return
			}
		case <-s.wake:
			for _, slot := range s.slots {
				select {
				case b := <-slot:
					if !write(b, true) {
						return
					}
				default:
				}
			}
		}
	}
}
