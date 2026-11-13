package events

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
)

// Sink consumes events. The same context passed to Publish is handed to the
// sink; consumers must not block on it for long.
type Sink func(ctx context.Context, e Event) error

// Option configures a Bus at construction time.
type Option func(*bus)

// WithPersist registers a synchronous persistence sink: invoked on every
// publish BEFORE fan-out. An error is logged but never blocks or fails the
// publisher. Use it for durability-critical records (audit, activity); keep
// the handler fast and internally retrying.
func WithPersist(s Sink) Option {
	return func(b *bus) { b.persist = append(b.persist, s) }
}

// WithBuffer sizes each subscriber's channel (default 256). A full buffer
// drops the newest event and counts it (visible via Stats).
func WithBuffer(n int) Option {
	return func(b *bus) {
		if n > 0 {
			b.buffer = n
		}
	}
}

// subscription is one registered consumer. Single goroutine drains ch; the
// queue is bounded, oldest-preserving, drop-newest.
type subscription struct {
	priority int
	ch       chan Event
	cancel   context.CancelFunc
	done     chan struct{}
	dropped  atomic.Uint64
}

func (s *subscription) deliver(e Event) {
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

// Bus is a correlation-aware in-process event bus.
type Bus struct {
	b *bus
}

type bus struct {
	mu       sync.RWMutex
	subs     map[Kind][]*subscription
	wildcard []*subscription // subscribes to every kind
	persist  []Sink
	buffer   int
	closed   atomic.Bool

	published atomic.Uint64
	wg        sync.WaitGroup
}

// New builds a Bus. Without subscribers publishes are cheap no-ops.
func New(opts ...Option) *Bus {
	b := &bus{subs: map[Kind][]*subscription{}, buffer: 256}
	for _, o := range opts {
		o(b)
	}
	return &Bus{b: b}
}

// Publish sends e to the bus: persist sinks first (synchronously), then async
// fan-out to subscribers of e.Kind and wildcard subscribers. Panic-safe: a
// panicking sink is caught and logged so a buggy consumer cannot take the
// process down.
func (b *Bus) Publish(ctx context.Context, e Event) {
	if b == nil || b.b == nil || b.b.closed.Load() {
		return
	}
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.TS.IsZero() {
		e.TS = Now()
	}
	if e.ParentID == "" {
		e.ParentID = CorrFrom(ctx)
	}
	b.b.published.Add(1)
	for _, p := range b.b.persist {
		if err := callSink(p, ctx, e); err != nil {
			log.Printf("[events] persist %s: %v", e.Kind, err)
		}
	}
	b.b.mu.RLock()
	subs := b.b.subs[e.Kind]
	snapshot := make([]*subscription, 0, len(subs)+len(b.b.wildcard))
	snapshot = append(snapshot, subs...)
	snapshot = append(snapshot, b.b.wildcard...)
	b.b.mu.RUnlock()
	if len(snapshot) == 0 {
		return
	}
	for _, s := range snapshot {
		s.deliver(e)
	}
}

// Subscribe registers sink for the given kinds (empty kinds = all kinds).
// Returns an unsubscribe function; after it returns, sink is guaranteed not to
// be invoked again. priority is a stable ordering hint for future persistence
// ordering only (not enforced for delivery).
func (b *Bus) Subscribe(kinds []Kind, priority int, sink Sink) func() {
	if b == nil || b.b == nil {
		return func() {}
	}
	s := &subscription{priority: priority, ch: make(chan Event, b.b.buffer)}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})

	b.b.mu.Lock()
	if len(kinds) == 0 {
		b.b.wildcard = append(b.b.wildcard, s)
	} else {
		for _, k := range kinds {
			b.b.subs[k] = append(b.b.subs[k], s)
		}
	}
	b.b.mu.Unlock()

	b.b.wg.Add(1)
	go func() {
		defer b.b.wg.Done()
		defer close(s.done)
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-s.ch:
				if err := callSink(sink, ctx, e); err != nil {
					log.Printf("[events] subscriber %s: %v", e.Kind, err)
				}
			}
		}
	}()
	return func() {
		cancel()
		<-s.done
		b.b.mu.Lock()
		b.b.removeLocked(s, kinds)
		b.b.mu.Unlock()
	}
}

// removeLocked detaches s once its goroutine has exited, so no new deliveries
// race the teardown.
func (b *bus) removeLocked(s *subscription, kinds []Kind) {
	if len(kinds) == 0 {
		keep := b.wildcard[:0]
		for _, w := range b.wildcard {
			if w != s {
				keep = append(keep, w)
			}
		}
		b.wildcard = keep
		return
	}
	for _, k := range kinds {
		list := b.subs[k]
		keep := list[:0]
		for _, sub := range list {
			if sub != s {
				keep = append(keep, sub)
			}
		}
		if len(keep) == 0 {
			delete(b.subs, k)
		} else {
			b.subs[k] = keep
		}
	}
}

// Stats is a cheap live snapshot for /metrics. Dropped sums every subscriber's
// drop counter (a full buffer drops the newest event).
type Stats struct {
	Published uint64
	Dropped   uint64
	Subs      uint64
}

func (b *Bus) Stats() Stats {
	if b == nil || b.b == nil {
		return Stats{}
	}
	b.b.mu.RLock()
	n := len(b.b.wildcard)
	var dropped uint64
	for _, list := range b.b.subs {
		n += len(list)
		for _, s := range list {
			dropped += s.dropped.Load()
		}
	}
	for _, s := range b.b.wildcard {
		dropped += s.dropped.Load()
	}
	b.b.mu.RUnlock()
	return Stats{
		Published: b.b.published.Load(),
		Dropped:   dropped,
		Subs:      uint64(n),
	}
}

// Close stops all subscriber goroutines and waits for them to drain. Further
// publishes become no-ops.
func (b *Bus) Close() {
	if b == nil || b.b == nil {
		return
	}
	if !b.b.closed.CompareAndSwap(false, true) {
		return
	}
	b.b.mu.RLock()
	subs := make([]*subscription, 0)
	for _, list := range b.b.subs {
		subs = append(subs, list...)
	}
	subs = append(subs, b.b.wildcard...)
	b.b.mu.RUnlock()
	for _, s := range subs {
		s.cancel()
	}
	b.b.wg.Wait()
}

// callSink recovers from a panicking sink and turns it into an error.
func callSink(s Sink, ctx context.Context, e Event) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sink panic: %v", r)
		}
	}()
	return s(ctx, e)
}
