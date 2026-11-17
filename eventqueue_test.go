package limb

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type eventRecorder struct {
	mu     sync.Mutex
	events []Event
	seen   []context.Context
}

func (r *eventRecorder) hook(ctx context.Context, e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	r.seen = append(r.seen, ctx)
}

func (r *eventRecorder) ids() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ids []string
	for _, e := range r.events {
		ids = append(ids, e.UserID)
	}
	return ids
}

func shutdownWithin(t *testing.T, a *Auth, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return a.Shutdown(ctx)
}

func newEventAuth(t *testing.T, hook func(context.Context, Event), opts ...Option) (*Auth, *fakeClock) {
	t.Helper()
	a, clock := newLimitedAuth(t, append([]Option{emailAndUsername(), WithHooks(Hooks{OnEvent: hook})}, opts...)...)
	t.Cleanup(func() { _ = shutdownWithin(t, a, 10*time.Second) })
	return a, clock
}

func TestAnEventForTheBackgroundReachesTheHookAfterTheCallerHasGone(t *testing.T) {
	gate := make(chan struct{})
	rec := &eventRecorder{}
	a, _ := newEventAuth(t, func(ctx context.Context, e Event) {
		<-gate
		rec.hook(ctx, e)
	})
	for _, id := range []string{"u1", "u2", "u3"} {
		a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: id})
	}
	if got := rec.ids(); len(got) != 0 {
		t.Fatalf("%v reached the hook while it was held up", got)
	}
	close(gate)
	eventually(t, "the events to reach the hook", func() bool { return len(rec.ids()) == 3 })
	if got := strings.Join(rec.ids(), ","); got != "u1,u2,u3" {
		t.Fatalf("the events came in the order %s, want the order of their registrations", got)
	}
}

type requestKey struct{}

func TestAnEventKeepsTheValuesOfTheRequestButNotItsEnd(t *testing.T) {
	type seen struct {
		value    any
		err      error
		deadline time.Time
	}
	got := make(chan seen, 1)
	a, _ := newEventAuth(t, func(ctx context.Context, _ Event) {
		deadline, _ := ctx.Deadline()
		got <- seen{value: ctx.Value(requestKey{}), err: ctx.Err(), deadline: deadline}
	})
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), requestKey{}, "request-7"))
	a.emitLater(ctx, Event{Type: EventUserCreated, UserID: "u1"})
	cancel()
	select {
	case s := <-got:
		if s.value != "request-7" || s.err != nil || s.deadline.IsZero() || time.Until(s.deadline) > eventTimeout {
			t.Fatalf("the hook saw %+v: it must see the values of the request, no end of it and a deadline of its own", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event did not reach the hook")
	}
}

func TestAnEventKeepsTheTimeOfWhatHappened(t *testing.T) {
	gate := make(chan struct{})
	rec := &eventRecorder{}
	a, clock := newEventAuth(t, func(ctx context.Context, e Event) {
		<-gate
		rec.hook(ctx, e)
	})
	happened := clock.now().UTC()
	a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: "u1", Details: map[string]string{"k": "v"}})
	clock.advance(time.Hour)
	close(gate)
	eventually(t, "the event to reach the hook", func() bool { return len(rec.ids()) == 1 })
	if e := rec.events[0]; !e.At.Equal(happened) || e.At.Location() != time.UTC || e.Details["k"] != "v" {
		t.Fatalf("event = %+v, want the time %v", e, happened)
	}
}

func TestAFullQueueDropsTheEventAndSaysSo(t *testing.T) {
	logger, logs := capturingLogger()
	gate := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	rec := &eventRecorder{}
	a, _ := newEventAuth(t, func(ctx context.Context, e Event) {
		once.Do(func() { close(entered) })
		<-gate
		rec.hook(ctx, e)
	}, WithLogger(logger))
	a.events = newEventQueue(1, a.callHook, logger)
	a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: "u1"})
	<-entered
	for _, id := range []string{"u2", "u3", "u4"} {
		a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: id})
	}
	close(gate)
	eventually(t, "the events to reach the hook", func() bool { return len(rec.ids()) == 2 })
	if got := strings.Join(rec.ids(), ","); got != "u1,u2" {
		t.Fatalf("delivered %s, want the first event and the one that fitted in the queue", got)
	}
	eventually(t, "the queue to count no event that was dropped", func() bool { return a.events.pending.Load() == 0 })
	if got := strings.Count(logs.String(), "the queue of events is full or stopped"); got != 2 {
		t.Fatalf("%d events were reported dropped, want 2:\n%s", got, logs.String())
	}
	_ = shutdownWithin(t, a, 5*time.Second)
}

func TestShutdownLetsTheWaitingEventsReachTheHook(t *testing.T) {
	gate := make(chan struct{})
	rec := &eventRecorder{}
	a, _ := newEventAuth(t, func(ctx context.Context, e Event) {
		<-gate
		rec.hook(ctx, e)
	})
	for _, id := range []string{"u1", "u2"} {
		a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: id})
	}
	done := make(chan error, 1)
	go func() { done <- shutdownWithin(t, a, 10*time.Second) }()
	select {
	case err := <-done:
		t.Fatalf("Shutdown returned %v before the events reached the hook", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if got := strings.Join(rec.ids(), ","); got != "u1,u2" {
		t.Fatalf("delivered %s", got)
	}
}

func TestShutdownGivesUpOnAHookThatDoesNotEnd(t *testing.T) {
	logger, logs := capturingLogger()
	canceled := make(chan struct{})
	entered := make(chan struct{})
	var calls atomic.Int32
	a, _ := newEventAuth(t, func(ctx context.Context, _ Event) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-ctx.Done()
		if calls.Load() == 1 {
			close(canceled)
		}
	}, WithLogger(logger))
	a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: "u1"})
	<-entered
	a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: "u2"})
	err := shutdownWithin(t, a, 50*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "2 events") {
		t.Fatalf("Shutdown = %v, want an error that counts the events that did not reach the hook", err)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("the context of the hook was not canceled")
	}
	if !strings.Contains(logs.String(), "the service stopped before all events reached the hook") {
		t.Fatalf("log:\n%s", logs.String())
	}
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("the hook was called %d times, the event that waited when the service was canceled must not reach it", got)
	}
}

func TestAnEventAfterShutdownIsDroppedAndSaid(t *testing.T) {
	logger, logs := capturingLogger()
	rec := &eventRecorder{}
	a, _ := newEventAuth(t, rec.hook, WithLogger(logger))
	if err := shutdownWithin(t, a, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: "u1"})
	if err := shutdownWithin(t, a, 5*time.Second); err != nil {
		t.Fatalf("a second Shutdown = %v", err)
	}
	if len(rec.ids()) != 0 || !strings.Contains(logs.String(), "the queue of events is full or stopped") {
		t.Fatalf("delivered %v, log:\n%s", rec.ids(), logs.String())
	}
}

func TestAPanicOfTheHookInTheBackgroundIsContained(t *testing.T) {
	logger, logs := capturingLogger()
	rec := &eventRecorder{}
	a, _ := newEventAuth(t, func(ctx context.Context, e Event) {
		if e.UserID == "boom" {
			panic("the invitation code is welcome-2026")
		}
		rec.hook(ctx, e)
	}, WithLogger(logger))
	a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: "boom"})
	a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: "fine"})
	eventually(t, "the second event to reach the hook", func() bool { return len(rec.ids()) == 1 })
	if strings.Contains(logs.String(), "welcome-2026") || !strings.Contains(logs.String(), "panic_type=string") {
		t.Fatalf("the log must name the type of the panic and not its value:\n%s", logs.String())
	}
}

func TestWithoutAHookOfEventsNothingIsQueued(t *testing.T) {
	a := newTestAuth(t, emailAndUsername())
	if a.events != nil {
		t.Fatal("a queue of events was made for a service that has no hook of events")
	}
	a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: "u1"})
	if err := shutdownWithin(t, a, time.Second); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
}

func TestShutdownReportsTheMessagesAndTheEventsThatWereLost(t *testing.T) {
	entered := make(chan struct{})
	f := newRecoveryFixture(t, manyRequests())
	f.a.hooks.OnEvent = func(ctx context.Context, _ Event) {
		close(entered)
		<-ctx.Done()
	}
	f.a.emitLater(t.Context(), Event{Type: EventUserCreated, UserID: "u1"})
	<-entered
	release := f.block(t)
	t.Cleanup(release)
	err := shutdownWithin(t, f.a, 50*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "messages were not sent") || !strings.Contains(err.Error(), "events did not reach the hook") {
		t.Fatalf("Shutdown = %v, want both the messages and the events counted", err)
	}
}
