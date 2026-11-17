package limb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/internal/memstore"
)

func fastOptions(workers, queue int) SendingOptions {
	return SendingOptions{Workers: workers, Queue: queue, Timeout: time.Minute}
}

func newTestDispatcher(t *testing.T, options SendingOptions, failed func(context.Context, task, error)) (*dispatcher, *logBuffer) {
	t.Helper()
	logger, logs := capturingLogger()
	d := newDispatcher(options, logger, failed)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.shutdown(ctx)
	})
	return d, logs
}

func idle(run func(ctx context.Context) error) task {
	return task{kind: MessageVerification, channel: "email", run: run}
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSendingOptionsDefaultsAndLimits(t *testing.T) {
	got, err := SendingOptions{}.resolve()
	if err != nil || got != (SendingOptions{Workers: 4, Queue: 256, Timeout: 30 * time.Second}) {
		t.Fatalf("resolve of the zero value = %+v, %v; want the defaults", got, err)
	}
	for _, o := range []SendingOptions{
		{Workers: 1, Queue: 1, Timeout: time.Second},
		{Workers: 64, Queue: 65536, Timeout: 10 * time.Minute},
		{Workers: 7},
		{Queue: 9},
		{Timeout: time.Minute},
	} {
		if resolved, resolveErr := o.resolve(); resolveErr != nil || resolved.Workers == 0 || resolved.Queue == 0 || resolved.Timeout == 0 {
			t.Errorf("resolve(%+v) = %+v, %v; want the value kept and the rest defaulted", o, resolved, resolveErr)
		}
	}
	for _, o := range []SendingOptions{
		{Workers: -1}, {Workers: 65}, {Queue: -1}, {Queue: 65537}, {Timeout: -time.Second}, {Timeout: time.Second - 1}, {Timeout: 10*time.Minute + 1},
	} {
		if _, resolveErr := o.resolve(); resolveErr == nil {
			t.Errorf("resolve(%+v) was accepted", o)
		}
	}
}

func TestNewRejectsBadSendingOptions(t *testing.T) {
	cases := map[string]SendingOptions{
		"negative workers":            {Workers: -1},
		"too many workers":            {Workers: 1000},
		"a negative queue":            {Queue: -5},
		"a queue that is too long":    {Queue: 100000},
		"a timeout that is too short": {Timeout: time.Millisecond},
		"a timeout that is too long":  {Timeout: time.Hour},
		"a negative timeout":          {Timeout: -time.Second},
	}
	for name, options := range cases {
		if _, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithSending(options)); err == nil {
			t.Errorf("%s: New accepted the options", name)
		}
	}
	good := SendingOptions{Workers: 2, Queue: 3, Timeout: 2 * time.Second}
	if _, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithSender(&recordingSender{}), WithSending(good)); err != nil {
		t.Fatalf("New refused good options: %v", err)
	}
}

type recordingSender struct {
	mu       sync.Mutex
	messages []Message
	err      error
}

func (s *recordingSender) Send(_ context.Context, m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, m)
	return s.err
}

func (s *recordingSender) sent() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

type senderFunc func(ctx context.Context, m Message) error

func (f senderFunc) Send(ctx context.Context, m Message) error { return f(ctx, m) }

func TestASlowSenderDoesNotHoldBackTheCaller(t *testing.T) {
	d, _ := newTestDispatcher(t, fastOptions(1, 4), nil)
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	begin := time.Now()
	err := d.submit(idle(func(ctx context.Context) error {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}))
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Fatalf("submit took %v although the task was still running", elapsed)
	}
	<-started
}

func TestAFullQueueIsRefusedWithBusy(t *testing.T) {
	d, _ := newTestDispatcher(t, fastOptions(1, 2), nil)
	started := make(chan struct{})
	release := make(chan struct{})
	var ran atomic.Int32
	block := idle(func(context.Context) error {
		ran.Add(1)
		started <- struct{}{}
		<-release
		return nil
	})
	if err := d.submit(block); err != nil {
		t.Fatal(err)
	}
	<-started
	quick := idle(func(context.Context) error { ran.Add(1); return nil })
	for range 2 {
		if err := d.submit(quick); err != nil {
			t.Fatalf("submit into a queue with room failed: %v", err)
		}
	}
	for range 3 {
		if err := d.submit(quick); !errors.Is(err, ErrBusy) {
			t.Fatalf("submit into a full queue = %v, want ErrBusy", err)
		}
	}
	if got := d.pending.Load(); got != 3 {
		t.Fatalf("%d tasks are pending, want the running one and the two that wait", got)
	}
	close(release)
	eventually(t, "the queue to drain", func() bool { return ran.Load() == 3 && d.pending.Load() == 0 })
	if err := d.submit(quick); err != nil {
		t.Fatalf("submit after the queue drained failed: %v", err)
	}
}

func TestTheWorkersRunTogetherUpToTheirNumber(t *testing.T) {
	d, _ := newTestDispatcher(t, fastOptions(3, 10), nil)
	var running, peak atomic.Int32
	gate := make(chan struct{})
	var done sync.WaitGroup
	work := idle(func(context.Context) error {
		defer done.Done()
		now := running.Add(1)
		for {
			old := peak.Load()
			if now <= old || peak.CompareAndSwap(old, now) {
				break
			}
		}
		<-gate
		running.Add(-1)
		return nil
	})
	done.Add(6)
	for range 6 {
		if err := d.submit(work); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "three workers to be busy", func() bool { return running.Load() == 3 })
	time.Sleep(20 * time.Millisecond)
	if got := running.Load(); got != 3 {
		t.Fatalf("%d tasks run at once, want 3", got)
	}
	close(gate)
	done.Wait()
	if got := peak.Load(); got != 3 {
		t.Fatalf("at most %d tasks ran at once, want 3", got)
	}
}

func TestAnUnusedDispatcherStartsNoWorkers(t *testing.T) {
	d, _ := newTestDispatcher(t, fastOptions(4, 4), nil)
	d.mu.Lock()
	started := d.started
	d.mu.Unlock()
	if started {
		t.Fatal("the workers started before the first message")
	}
	if err := d.shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown of a dispatcher that never ran = %v", err)
	}
}

func TestTheTimeoutEndsATaskThatWaitsForItsContext(t *testing.T) {
	failures := make(chan error, 1)
	options := SendingOptions{Workers: 1, Queue: 1, Timeout: 30 * time.Millisecond}
	d, logs := newTestDispatcher(t, options, func(_ context.Context, _ task, err error) { failures <- err })
	err := d.submit(idle(func(ctx context.Context) error {
		<-ctx.Done()
		return fmt.Errorf("stopped: %w", ctx.Err())
	}))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-failures:
		if !errors.Is(got, context.DeadlineExceeded) {
			t.Fatalf("the failure is %v, want the deadline", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the timeout did not end the task")
	}
	eventually(t, "the log line", func() bool { return strings.Contains(logs.String(), "a message was not sent") })
	for _, want := range []string{"kind=verification", "channel=email"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the log lacks %q: %s", want, logs.String())
		}
	}
}

func TestAPanicInATaskIsContainedAndReported(t *testing.T) {
	failures := make(chan error, 4)
	d, logs := newTestDispatcher(t, fastOptions(1, 4), func(_ context.Context, _ task, err error) { failures <- err })
	if err := d.submit(idle(func(context.Context) error { panic("the secret code 123456 and https://x/#token=abc") })); err != nil {
		t.Fatal(err)
	}
	var after atomic.Bool
	if err := d.submit(idle(func(context.Context) error { after.Store(true); return nil })); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-failures:
		if !strings.Contains(got.Error(), "panicked with a value of type string") || strings.Contains(got.Error(), "123456") {
			t.Fatalf("the failure of a panic = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the panic was not reported")
	}
	eventually(t, "the next task", after.Load)
	if strings.Contains(logs.String(), "123456") || strings.Contains(logs.String(), "token=abc") {
		t.Fatalf("the log has the value of the panic: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "panic_type=string") {
		t.Fatalf("the log lacks the type of the panic: %s", logs.String())
	}
}

func TestShutdownLetsTheWaitingMessagesGoOut(t *testing.T) {
	d, _ := newTestDispatcher(t, fastOptions(2, 50), nil)
	var ran atomic.Int32
	for range 40 {
		err := d.submit(idle(func(context.Context) error {
			time.Sleep(time.Millisecond)
			ran.Add(1)
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.shutdown(ctx); err != nil {
		t.Fatalf("shutdown = %v, want nil after everything was sent", err)
	}
	if ran.Load() != 40 {
		t.Fatalf("%d messages went out, want 40", ran.Load())
	}
	if err := d.submit(idle(func(context.Context) error { return nil })); !errors.Is(err, ErrBusy) {
		t.Fatalf("submit after shutdown = %v, want ErrBusy", err)
	}
	if err := d.shutdown(ctx); err != nil {
		t.Fatalf("a second shutdown = %v, want nil", err)
	}
}

func TestShutdownThatRunsOutOfTimeCancelsAndCountsTheLostMessages(t *testing.T) {
	d, logs := newTestDispatcher(t, fastOptions(1, 10), nil)
	started := make(chan struct{})
	var ran atomic.Int32
	err := d.submit(idle(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}))
	if err != nil {
		t.Fatal(err)
	}
	<-started
	for range 5 {
		if err = d.submit(idle(func(context.Context) error { ran.Add(1); return nil })); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = d.shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "6 messages") {
		t.Fatalf("shutdown = %v, want an error that counts the 6 messages that were lost", err)
	}
	if !strings.Contains(logs.String(), "unsent=6") {
		t.Fatalf("the log does not say how many messages were lost: %s", logs.String())
	}
	eventually(t, "the queue to be emptied", func() bool { return d.pending.Load() == 0 })
	if ran.Load() != 0 {
		t.Fatalf("%d tasks ran after the shutdown gave up, want none", ran.Load())
	}
}

func TestSubmitsRacingWithShutdownNeverPanic(t *testing.T) {
	for range 20 {
		d := newDispatcher(fastOptions(2, 8), discardingLogger(), nil)
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for range 50 {
					if err := d.submit(idle(func(context.Context) error { return nil })); err != nil && !errors.Is(err, ErrBusy) {
						t.Errorf("submit failed with %v", err)
					}
				}
			})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := d.shutdown(ctx); err != nil {
			t.Errorf("shutdown = %v", err)
		}
		cancel()
		wg.Wait()
	}
}

func TestShutdownOfAServiceWithoutASenderDoesNothing(t *testing.T) {
	a := newTestAuth(t)
	if err := a.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown = %v, want nil", err)
	}
}

func TestShutdownOfAServiceStopsItsDispatcher(t *testing.T) {
	a := newTestAuth(t, WithSender(&recordingSender{}))
	if a.dispatcher == nil {
		t.Fatal("a service with a Sender has no dispatcher")
	}
	var ran atomic.Bool
	if err := a.dispatcher.submit(idle(func(context.Context) error { ran.Store(true); return nil })); err != nil {
		t.Fatal(err)
	}
	if err := a.Shutdown(t.Context()); err != nil || !ran.Load() {
		t.Fatalf("Shutdown = %v, ran %v; want the message sent first", err, ran.Load())
	}
	if err := a.dispatcher.submit(idle(func(context.Context) error { return nil })); !errors.Is(err, ErrBusy) {
		t.Fatalf("submit after Shutdown = %v, want ErrBusy", err)
	}
}

var testLinkToken = strings.Repeat("Q", 24)

func newTestMessage() Message {
	return Message{
		Kind: MessagePasswordReset, UserID: "u-1", Channel: "email", To: "alice@example.com", Language: "en",
		Subject: "Reset", Text: "text", Link: "https://app.example.com/reset#token=" + testLinkToken, Code: "123456",
	}
}

func TestDeliverPassesTheMessageToTheSender(t *testing.T) {
	sender := &recordingSender{}
	a := newTestAuth(t, WithSender(sender))
	want := newTestMessage()
	if err := a.deliver(t.Context(), want); err != nil {
		t.Fatalf("deliver = %v", err)
	}
	if got := sender.sent(); len(got) != 1 || got[0] != want {
		t.Fatalf("the sender got %+v, want %+v", got, want)
	}
}

func TestDeliverHidesTheSecretsInTheErrorOfTheSender(t *testing.T) {
	m := newTestMessage()
	echoes := []string{
		"smtp: rejected " + m.To,
		"gateway said: " + m.Link,
		"bad body: code " + m.Code,
		"bad token " + strings.TrimPrefix(m.Link, "https://app.example.com/reset#token="),
		"bad fragment " + strings.TrimPrefix(m.Link, "https://app.example.com/reset#"),
		m.Code + m.Code + m.To + m.Link,
	}
	for _, echo := range echoes {
		a := newTestAuth(t, WithSender(senderFunc(func(context.Context, Message) error { return errors.New(echo) })))
		err := a.deliver(t.Context(), m)
		if err == nil {
			t.Fatalf("deliver of %q returned nil", echo)
		}
		for _, hidden := range []string{m.To, m.Link, m.Code, testLinkToken, "token="} {
			if strings.Contains(err.Error(), hidden) {
				t.Errorf("the error %q contains %q", err, hidden)
			}
		}
		for _, want := range []string{"password_reset", "email", "a***@example.com"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error %q lacks %q", err, want)
			}
		}
	}
}

func TestDeliverKeepsTheReasonOfAnErrorThatHasNoSecret(t *testing.T) {
	a := newTestAuth(t, WithSender(senderFunc(func(context.Context, Message) error { return errors.New("dial tcp: connection refused") })))
	err := a.deliver(t.Context(), newTestMessage())
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("deliver = %v, want the reason to be kept", err)
	}
	var failure *deliveryError
	if !errors.As(err, &failure) || failure.kind != MessagePasswordReset || failure.channel != "email" {
		t.Fatalf("deliver returned %T, want a *deliveryError that names the message", err)
	}
}

func TestDeliverDoesNotGarbleTheErrorOfAMessageWithoutSecrets(t *testing.T) {
	a := newTestAuth(t, WithSender(senderFunc(func(context.Context, Message) error { return errors.New("dial tcp: connection refused") })))
	notice := Message{Kind: MessagePasswordChanged, UserID: "u-1", Channel: "email", To: "alice@example.com", Language: "en", Subject: "s", Text: "t"}
	err := a.deliver(t.Context(), notice)
	want := "limb: send a password_changed message to email a***@example.com: dial tcp: connection refused"
	if err == nil || err.Error() != want {
		t.Fatalf("deliver = %v, want %q", err, want)
	}
}

func TestDeliverSaysWhenTheSendingTimedOutOrWasCanceled(t *testing.T) {
	waits := senderFunc(func(ctx context.Context, _ Message) error {
		<-ctx.Done()
		return fmt.Errorf("giving up on %s: %w", "alice@example.com", ctx.Err())
	})
	a := newTestAuth(t, WithSender(waits))
	timed, cancelTimed := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancelTimed()
	if err := a.deliver(timed, newTestMessage()); err == nil || !strings.Contains(err.Error(), "timed out") || strings.Contains(err.Error(), "alice@example.com") {
		t.Errorf("deliver after the timeout = %v, want a timeout without the address", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := a.deliver(canceled, newTestMessage()); err == nil || !strings.Contains(err.Error(), "the sending was canceled") || strings.Contains(err.Error(), "giving up") {
		t.Errorf("deliver after the cancel = %v, want a cancel", err)
	}
	silent := newTestAuth(t, WithSender(senderFunc(func(context.Context, Message) error { return errors.New("it says nothing of the context") })))
	late, cancelLate := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancelLate()
	<-late.Done()
	if err := silent.deliver(late, newTestMessage()); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("deliver of an error that came after the deadline = %v, want a timeout", err)
	}
	own := newTestAuth(t, WithSender(senderFunc(func(context.Context, Message) error {
		return fmt.Errorf("smtp to alice@example.com: %w", context.DeadlineExceeded)
	})))
	if err := own.deliver(t.Context(), newTestMessage()); err == nil || !strings.Contains(err.Error(), "the sending timed out") || strings.Contains(err.Error(), "smtp") {
		t.Errorf("deliver of a timeout of the sender itself = %v, want the plain timeout", err)
	}
	ownCancel := newTestAuth(t, WithSender(senderFunc(func(context.Context, Message) error {
		return fmt.Errorf("smtp to alice@example.com: %w", context.Canceled)
	})))
	if err := ownCancel.deliver(t.Context(), newTestMessage()); err == nil || !strings.Contains(err.Error(), "the sending was canceled") || strings.Contains(err.Error(), "smtp") {
		t.Errorf("deliver of a cancel of the sender itself = %v, want the plain cancel", err)
	}
}

func TestDeliverContainsAPanicOfTheSender(t *testing.T) {
	m := newTestMessage()
	a := newTestAuth(t, WithSender(senderFunc(func(_ context.Context, got Message) error { panic("boom " + got.Code + " " + got.Link) })))
	err := a.deliver(t.Context(), m)
	if err == nil || !strings.Contains(err.Error(), "panicked with a value of type string") {
		t.Fatalf("deliver = %v, want an error about the panic", err)
	}
	for _, secret := range []string{m.Code, m.Link, m.To} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error %q contains %q", err, secret)
		}
	}
}

func TestMaskValue(t *testing.T) {
	cases := map[string]string{
		"alice@example.com": "a***@example.com",
		"a@example.com":     "a***@example.com",
		"яна@пример.рф":     "я***@пример.рф",
		"+15550100":         "+1***00",
		"+79991234567":      "+7***67",
		"1234567":           "12***67",
		"123456":            "***",
		"abc":               "***",
		"":                  "***",
		"@example.com":      "@e***om",
		"alice@":            "***",
		"@":                 "***",
	}
	for value, want := range cases {
		if got := maskValue(value); got != want {
			t.Errorf("maskValue(%q) = %q, want %q", value, got, want)
		}
	}
}
