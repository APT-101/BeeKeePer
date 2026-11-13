package events

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func testEvent(kind Kind) Event { return NewEvent(kind) }

func TestPublishFillsFieldsAndInheritsCorr(t *testing.T) {
	b := New(WithBuffer(8))
	defer b.Close()

	got := make(chan Event, 1)
	unsub := b.Subscribe([]Kind{EvToolCalled}, 0, func(_ context.Context, e Event) error {
		got <- e
		return nil
	})
	defer unsub()

	ctx := WithCorr(context.Background(), "corr-123")
	b.Publish(ctx, Event{Kind: EvToolCalled})

	select {
	case e := <-got:
		if e.ID == "" {
			t.Error("ID not filled")
		}
		if e.TS.IsZero() {
			t.Error("TS not filled")
		}
		if e.ParentID != "corr-123" {
			t.Errorf("ParentID = %q, want corr-123 (inherited from ctx)", e.ParentID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber did not receive event")
	}
}

func TestSubscribeFiltersByKind(t *testing.T) {
	b := New(WithBuffer(8))
	defer b.Close()

	var toolEvents atomic.Int64
	b.Subscribe([]Kind{EvToolCalled, EvToolResult}, 0, func(_ context.Context, e Event) error {
		toolEvents.Add(1)
		return nil
	})
	var findingEvents atomic.Int64
	b.Subscribe([]Kind{EvFindingReported}, 0, func(_ context.Context, e Event) error {
		findingEvents.Add(1)
		return nil
	})

	ctx := context.Background()
	b.Publish(ctx, testEvent(EvToolCalled))
	b.Publish(ctx, testEvent(EvToolDenied)) // not subscribed anywhere
	b.Publish(ctx, testEvent(EvFindingReported))

	// give the async fan-out a moment
	deadline := time.Now().Add(time.Second)
	for toolEvents.Load() != 1 || findingEvents.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("tool=%d finding=%d, want 1 and 1", toolEvents.Load(), findingEvents.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWildcardSubscriber(t *testing.T) {
	b := New(WithBuffer(16))
	defer b.Close()

	var n atomic.Int64
	b.Subscribe(nil, 0, func(_ context.Context, e Event) error { n.Add(1); return nil })

	for i := 0; i < 5; i++ {
		b.Publish(context.Background(), testEvent(EvPlannerRound))
	}
	deadline := time.Now().Add(time.Second)
	for n.Load() != 5 {
		if time.Now().After(deadline) {
			t.Fatalf("wildcard received %d, want 5", n.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	b := New(WithBuffer(4))
	defer b.Close()

	var n atomic.Int64
	unsub := b.Subscribe(nil, 0, func(_ context.Context, e Event) error { n.Add(1); return nil })

	b.Publish(context.Background(), testEvent(EvToolCalled))
	deadline := time.Now().Add(time.Second)
	for n.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no delivery before unsubscribe")
		}
		time.Sleep(5 * time.Millisecond)
	}

	unsub()
	before := n.Load()
	b.Publish(context.Background(), testEvent(EvToolCalled))
	time.Sleep(50 * time.Millisecond)
	if n.Load() != before {
		t.Fatalf("delivered after unsubscribe: %d -> %d", before, n.Load())
	}
}

func TestDropOnFullBufferCounted(t *testing.T) {
	b := New(WithBuffer(2))
	defer b.Close()

	// slow subscriber that never drains
	unsub := b.Subscribe([]Kind{EvToolCalled}, 0, func(_ context.Context, e Event) error {
		time.Sleep(10 * time.Millisecond)
		return nil
	})
	defer unsub()

	ctx := context.Background()
	for i := 0; i < 50; i++ {
		b.Publish(ctx, testEvent(EvToolCalled))
	}
	// give the drainer a moment to count drops
	time.Sleep(100 * time.Millisecond)
	stats := b.Stats()
	if stats.Dropped == 0 {
		t.Error("expected dropped events to be counted")
	}
	if stats.Published != 50 {
		t.Errorf("Published = %d, want 50", stats.Published)
	}
}

func TestPersistSinkSyncAndPanicSafe(t *testing.T) {
	var persisted atomic.Int64
	var panicking atomic.Bool
	b := New(
		WithBuffer(4),
		WithPersist(func(_ context.Context, e Event) error { persisted.Add(1); return nil }),
		// a broken persist sink must not take the publisher down
		WithPersist(func(_ context.Context, e Event) error {
			if panicking.Load() {
				panic("boom")
			}
			return nil
		}),
	)
	defer b.Close()

	b.Publish(context.Background(), testEvent(EvSessionStarted))
	b.Publish(context.Background(), testEvent(EvSessionStarted))
	if persisted.Load() != 2 {
		t.Fatalf("persist called %d times, want 2", persisted.Load())
	}
	panicking.Store(true)
	b.Publish(context.Background(), testEvent(EvSessionStarted)) // must not panic
	panicking.Store(false)
}

func TestCloseMakesPublishNoop(t *testing.T) {
	b := New(WithBuffer(4))
	var n atomic.Int64
	b.Subscribe(nil, 0, func(_ context.Context, e Event) error { n.Add(1); return nil })
	b.Close() // must not deadlock
	b.Publish(context.Background(), testEvent(EvToolCalled))
	time.Sleep(50 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatalf("received %d events after Close", n.Load())
	}
}
