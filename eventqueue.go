package limb

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	eventQueueSize = 256
	eventTimeout   = 30 * time.Second

	eventsLostWarning  = "limb: the service stopped before all events reached the hook"
	eventsLostError    = "limb: %d events did not reach the hook before the deadline: %w"
	recordsLostWarning = "limb: the service stopped before all audit records were written"
	recordsLostError   = "limb: %d audit records were not written before the deadline: %w"
)

type queuedEvent struct {
	values context.Context
	event  Event
}

type eventQueue struct {
	deliver func(ctx context.Context, e Event)
	logger  *slog.Logger
	events  chan queuedEvent
	base    context.Context
	cancel  context.CancelFunc
	pending atomic.Int64
	worker  sync.WaitGroup

	lostWarning string
	lostError   string

	mu      sync.Mutex
	started bool
	closed  bool
}

func newEventQueue(size int, deliver func(ctx context.Context, e Event), logger *slog.Logger) *eventQueue {
	base, cancel := context.WithCancel(context.Background())
	return &eventQueue{
		deliver:     deliver,
		logger:      logger,
		events:      make(chan queuedEvent, size),
		base:        base,
		cancel:      cancel,
		lostWarning: eventsLostWarning,
		lostError:   eventsLostError,
	}
}

func newRecordQueue(size int, write func(ctx context.Context, e Event), logger *slog.Logger) *eventQueue {
	q := newEventQueue(size, write, logger)
	q.lostWarning, q.lostError = recordsLostWarning, recordsLostError
	return q
}

func (q *eventQueue) add(values context.Context, e Event) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	if !q.started {
		q.started = true
		q.worker.Go(q.work)
	}
	q.pending.Add(1)
	select {
	case q.events <- queuedEvent{values: values, event: e}:
		return true
	default:
		q.pending.Add(-1)
		return false
	}
}

func (q *eventQueue) work() {
	for item := range q.events {
		q.run(item)
	}
}

func (q *eventQueue) run(item queuedEvent) {
	defer q.pending.Add(-1)
	if q.base.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(q.base, eventTimeout)
	defer cancel()
	q.deliver(requestValues{Context: ctx, values: item.values}, item.event)
}

func (q *eventQueue) shutdown(ctx context.Context) error {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.events)
	}
	q.mu.Unlock()
	done := make(chan struct{})
	go func() {
		q.worker.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
	}
	q.cancel()
	lost := q.pending.Load()
	q.logger.Warn(q.lostWarning, "lost", lost)
	return fmt.Errorf(q.lostError, lost, ctx.Err())
}

type requestValues struct {
	context.Context
	values context.Context
}

func (c requestValues) Value(key any) any {
	if v := c.values.Value(key); v != nil {
		return v
	}
	return c.Context.Value(key)
}
