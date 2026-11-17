package limb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultSendWorkers = 4
	defaultSendQueue   = 256
	defaultSendTimeout = 30 * time.Second

	maxSendWorkers = 64
	maxSendQueue   = 1 << 16
	minSendTimeout = time.Second
	maxSendTimeout = 10 * time.Minute

	redacted        = "[removed]"
	minHiddenLength = 4
)

// ErrBusy is returned when limb cannot take another message to send, because
// the queue of the background sending is full or the service is shutting down.
// It does not depend on who asks or whom the message is for, so it tells nothing
// about the accounts. The HTTP handler answers it with 503 and a Retry-After
// header.
var ErrBusy = errors.New("limb: too many messages are waiting to be sent, try again later")

// SendingOptions tune the background sending of messages, see WithSending. A
// field that is zero keeps its default.
type SendingOptions struct {
	// Workers is how many messages are sent at the same time, 4 by default, at
	// most 64.
	Workers int
	// Queue is how many messages can wait for a free worker, 256 by default, at
	// most 65536. A message that finds the queue full is refused with ErrBusy.
	Queue int
	// Timeout is how long one message may take, from the moment a worker takes it
	// to the end of Sender.Send, 30 seconds by default, between a second and ten
	// minutes.
	Timeout time.Duration
}

// WithSending tunes the background sending of messages: how many workers send
// them, how many messages may wait and how long one of them may take. New fails
// for a value that is negative or out of range.
//
// A request that causes a message does not wait for it: it puts a task in the
// queue and answers, so the time of the answer depends neither on the speed of
// the Sender nor on whether the account exists. The queue lives in the memory of
// the process. A message that was waiting when the process stopped is lost, and
// that costs the user a repeated request: the secrets of a message that was not
// sent are stored only as hashes, nobody can read them, and they expire. Call
// Auth.Shutdown after http.Server.Shutdown to let the messages that wait go out.
func WithSending(o SendingOptions) Option {
	return func(c *config) {
		c.sending = o
	}
}

func (o SendingOptions) resolve() (SendingOptions, error) {
	if o.Workers < 0 || o.Workers > maxSendWorkers {
		return o, fmt.Errorf("limb: the number of workers that send messages must be between 1 and %d", maxSendWorkers)
	}
	if o.Queue < 0 || o.Queue > maxSendQueue {
		return o, fmt.Errorf("limb: the queue of messages must hold between 1 and %d messages", maxSendQueue)
	}
	if o.Timeout != 0 && (o.Timeout < minSendTimeout || o.Timeout > maxSendTimeout) {
		return o, fmt.Errorf("limb: the time to send a message must be between %s and %s", minSendTimeout, maxSendTimeout)
	}
	if o.Workers == 0 {
		o.Workers = defaultSendWorkers
	}
	if o.Queue == 0 {
		o.Queue = defaultSendQueue
	}
	if o.Timeout == 0 {
		o.Timeout = defaultSendTimeout
	}
	return o, nil
}

type task struct {
	kind    MessageKind
	channel string
	run     func(ctx context.Context) error
}

type dispatcher struct {
	options SendingOptions
	logger  *slog.Logger
	failed  func(ctx context.Context, t task, err error)
	queue   chan task
	base    context.Context
	cancel  context.CancelFunc
	pending atomic.Int64
	workers sync.WaitGroup

	mu      sync.Mutex
	started bool
	closed  bool
}

func newDispatcher(options SendingOptions, logger *slog.Logger, failed func(ctx context.Context, t task, err error)) *dispatcher {
	base, cancel := context.WithCancel(context.Background())
	return &dispatcher{
		options: options,
		logger:  logger,
		failed:  failed,
		queue:   make(chan task, options.Queue),
		base:    base,
		cancel:  cancel,
	}
}

func (d *dispatcher) submit(t task) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrBusy
	}
	if !d.started {
		d.started = true
		for range d.options.Workers {
			d.workers.Go(d.work)
		}
	}
	d.pending.Add(1)
	select {
	case d.queue <- t:
		return nil
	default:
		d.pending.Add(-1)
		return ErrBusy
	}
}

func (d *dispatcher) work() {
	for t := range d.queue {
		d.execute(t)
	}
}

func (d *dispatcher) execute(t task) {
	defer d.pending.Add(-1)
	if d.base.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(d.base, d.options.Timeout)
	defer cancel()
	err := d.guarded(ctx, t)
	if err == nil {
		return
	}
	d.logger.WarnContext(ctx, "limb: a message was not sent", "kind", t.kind, "channel", t.channel, "error", err)
	if d.failed != nil {
		d.failed(ctx, t, err)
	}
}

func (d *dispatcher) guarded(ctx context.Context, t task) (err error) {
	defer func() {
		if r := recover(); r != nil {
			d.logger.ErrorContext(ctx, "limb: the task of a message panicked", "kind", t.kind, "channel", t.channel,
				"panic_type", fmt.Sprintf("%T", r), "stack", string(debug.Stack()))
			err = fmt.Errorf("limb: the task of a %s message panicked with a value of type %T", t.kind, r)
		}
	}()
	return t.run(ctx)
}

func (d *dispatcher) shutdown(ctx context.Context) error {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.queue)
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() {
		d.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
	}
	d.cancel()
	unsent := d.pending.Load()
	d.logger.Warn("limb: the service stopped before all messages were sent", "unsent", unsent)
	return fmt.Errorf("limb: %d messages were not sent before the deadline: %w", unsent, ctx.Err())
}

// Shutdown stops the background work: it takes no new messages, lets the
// messages that wait go out and waits for the workers until ctx ends. When ctx
// ends first, the sending that is still running is canceled, and the number of
// messages that were lost is logged and returned in the error. Call it after
// http.Server.Shutdown, so that no request is left to add messages. Messages
// that cannot be sent after the call are refused with ErrBusy. The events that
// wait to reach Hooks.OnEvent and the records of the audit log that wait to be
// written get the same treatment, after the messages.
func (a *Auth) Shutdown(ctx context.Context) error {
	var sending, events, records error
	if a.dispatcher != nil {
		sending = a.dispatcher.shutdown(ctx)
	}
	if a.events != nil {
		events = a.events.shutdown(ctx)
	}
	if a.auditing != nil {
		records = a.auditing.shutdown(ctx)
	}
	return errors.Join(sending, events, records)
}

type deliveryError struct {
	kind      MessageKind
	userID    string
	channel   string
	recipient string
	code      string
	reason    string
}

func (e *deliveryError) Error() string {
	return fmt.Sprintf("limb: send a %s message to %s %s: %s", e.kind, e.channel, e.recipient, e.reason)
}

func asDeliveryError(err error) (*deliveryError, bool) {
	var failure *deliveryError
	return failure, errors.As(err, &failure)
}

func failureOf(m Message, code, reason string) error {
	return &deliveryError{kind: m.Kind, userID: m.UserID, channel: m.Channel, recipient: maskValue(m.To), code: code, reason: reason}
}

func (a *Auth) deliver(ctx context.Context, m Message) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = failureOf(m, "panic", fmt.Sprintf("the sender panicked with a value of type %T", r))
		}
	}()
	sendErr := a.sender.Send(ctx, m)
	switch {
	case sendErr == nil:
		return nil
	case errors.Is(sendErr, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return failureOf(m, "timeout", "the sending timed out")
	case errors.Is(sendErr, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return failureOf(m, "canceled", "the sending was canceled")
	}
	return failureOf(m, "rejected", scrub(sendErr.Error(), m))
}

func scrub(text string, m Message) string {
	hidden := []string{m.Link, m.Code, m.To}
	if _, fragment, found := strings.Cut(m.Link, "#"); found {
		hidden = append(hidden, fragment, strings.TrimPrefix(fragment, "token="))
	}
	for _, secret := range hidden {
		if len(secret) >= minHiddenLength {
			text = strings.ReplaceAll(text, secret, redacted)
		}
	}
	return text
}

func maskValue(value string) string {
	if local, domain, found := strings.Cut(value, "@"); found && local != "" && domain != "" {
		runes := []rune(local)
		return string(runes[:1]) + "***@" + domain
	}
	runes := []rune(value)
	if len(runes) <= 6 {
		return "***"
	}
	return string(runes[:2]) + "***" + string(runes[len(runes)-2:])
}
