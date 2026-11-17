package limb

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) hooks() Hooks {
	return Hooks{OnEvent: func(_ context.Context, e Event) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.events = append(l.events, e)
	}}
}

func (l *eventLog) take() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	taken := l.events
	l.events = nil
	return taken
}

func typesOf(events []Event) []EventType {
	types := make([]EventType, len(events))
	for i, e := range events {
		types[i] = e.Type
	}
	return types
}

func newEventFixture(t *testing.T, opts ...Option) (*sessionFixture, *eventLog) {
	t.Helper()
	log := &eventLog{}
	f := newSessionFixture(t, append([]Option{WithHooks(log.hooks())}, opts...)...)
	log.take()
	return f, log
}

func wantTypes(t *testing.T, got []Event, want ...EventType) {
	t.Helper()
	types := typesOf(got)
	if len(types) != len(want) {
		t.Fatalf("events = %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("events = %v, want %v", types, want)
		}
	}
}

func TestARegistrationReportsTheNewUserAfterItIsStored(t *testing.T) {
	f, log := newEventFixture(t)
	var seen bool
	f.a.hooks.OnEvent = func(ctx context.Context, e Event) {
		if e.Type != EventUserCreated {
			return
		}
		_, err := f.a.store.Users().Get(ctx, f.a.tenant, e.UserID)
		seen = err == nil
		log.hooks().OnEvent(ctx, e)
	}
	user := mustRegister(t, f.a, map[string]string{"email": "bob@example.com"}, goodPassword)
	events := log.take()
	wantTypes(t, events, EventUserCreated)
	if events[0].UserID != string(user.ID) || !events[0].At.Equal(f.clock.now()) || events[0].SessionID != "" || events[0].Address != "" || !seen {
		t.Fatalf("event = %+v (the user was stored when the hook ran: %v)", events[0], seen)
	}
	if events[0].At.Location() != time.UTC {
		t.Fatalf("the time of the event is in %v, want UTC", events[0].At.Location())
	}
}

func TestALoginReportsTheSessionTheAddressAndTheKind(t *testing.T) {
	f, log := newEventFixture(t)
	cookie := f.login(t)
	token := f.tokenLogin(t)
	events := log.take()
	wantTypes(t, events, EventLogin, EventLogin)
	for i, want := range []struct {
		login Login
		kind  string
	}{{cookie, "cookie"}, {token, "token"}} {
		e := events[i]
		if e.UserID != string(f.user.ID) || e.SessionID != want.login.Principal.SessionID || e.IP != testIP.String() ||
			e.Details["kind"] != want.kind || !e.At.Equal(f.clock.now()) || e.Address != "" {
			t.Errorf("event %d = %+v, want the user, the session %s, the address and the kind %s", i, e, want.login.Principal.SessionID, want.kind)
		}
	}
}

func TestAFailedLoginIsReportedWithAMaskedLogin(t *testing.T) {
	f, log := newEventFixture(t)
	c := f.credentials()
	c.Password = "the wrong password"
	if _, err := f.a.Login(t.Context(), c); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v", err)
	}
	c.Login = "nobody@example.com"
	if _, err := f.a.Login(t.Context(), c); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v", err)
	}
	events := log.take()
	wantTypes(t, events, EventLoginFailed, EventLoginFailed)
	known, unknown := events[0], events[1]
	if known.UserID != string(f.user.ID) || known.Address != "n***@example.com" || known.Details["reason"] != "invalid_credentials" || known.IP != testIP.String() {
		t.Errorf("the event of a wrong password = %+v", known)
	}
	if unknown.UserID != "" || unknown.Address != "n***@example.com" || unknown.Details["reason"] != "invalid_credentials" {
		t.Errorf("the event of an unknown login = %+v: it must have no user and the same shape", unknown)
	}
	for _, e := range events {
		if strings.Contains(e.Address, "nina") || strings.Contains(e.Address, "nobody") {
			t.Errorf("the address of the event is not masked: %q", e.Address)
		}
	}
}

func TestABlockedAccountIsReportedAsABlockedLogin(t *testing.T) {
	f, log := newEventFixture(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	if _, err := f.a.Login(t.Context(), f.credentials()); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("Login = %v", err)
	}
	events := log.take()
	wantTypes(t, events, EventLoginFailed)
	if events[0].Details["reason"] != "blocked" || events[0].UserID != string(f.user.ID) {
		t.Fatalf("event = %+v", events[0])
	}
}

func TestAttemptsThatTheLimitsTurnDownAreNotReported(t *testing.T) {
	f, log := newEventFixture(t, WithLoginLimits(LoginLimits{AccountAndIP: Limit{Attempts: 2, Window: time.Hour, Pause: time.Hour}}))
	c := f.credentials()
	c.Password = "the wrong password"
	for range 2 {
		if _, err := f.a.Login(t.Context(), c); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login = %v", err)
		}
	}
	log.take()
	if _, err := f.a.Login(t.Context(), c); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Login = %v, want it to be turned down", err)
	}
	if events := log.take(); len(events) != 0 {
		t.Fatalf("an attempt that the limits turned down was reported: %+v", events)
	}
}

func TestLogoutIsReportedOnlyWhenASessionEnded(t *testing.T) {
	f, log := newEventFixture(t)
	login := f.login(t)
	log.take()
	if err := f.a.Logout(t.Context(), login.Principal); err != nil {
		t.Fatal(err)
	}
	events := log.take()
	wantTypes(t, events, EventLogout)
	if events[0].UserID != string(f.user.ID) || events[0].SessionID != login.Principal.SessionID {
		t.Fatalf("event = %+v", events[0])
	}
	if err := f.a.Logout(t.Context(), login.Principal); err != nil {
		t.Fatal(err)
	}
	if events = log.take(); len(events) != 0 {
		t.Fatalf("a second logout was reported: %+v", events)
	}
}

func TestEndingSessionsIsReportedWithTheReasonAndTheCount(t *testing.T) {
	f, log := newEventFixture(t)
	first, second := f.login(t), f.login(t)
	log.take()
	if err := f.a.TerminateSession(t.Context(), first.Principal, second.Principal.SessionID, ""); err != nil {
		t.Fatal(err)
	}
	events := log.take()
	wantTypes(t, events, EventSessionEnded)
	if events[0].SessionID != second.Principal.SessionID || events[0].Details["reason"] != "terminated" || events[0].Details["count"] != "1" {
		t.Fatalf("event = %+v", events[0])
	}
	third := f.login(t)
	log.take()
	if err := f.a.LogoutAll(t.Context(), third.Principal, ""); err != nil {
		t.Fatal(err)
	}
	events = log.take()
	wantTypes(t, events, EventSessionEnded)
	if events[0].Details["reason"] != "logout_all" || events[0].Details["count"] != "2" || events[0].UserID != string(f.user.ID) {
		t.Fatalf("event = %+v", events[0])
	}
	if err := f.a.LogoutAll(t.Context(), third.Principal, ""); err != nil {
		t.Fatal(err)
	}
	if events = log.take(); len(events) != 0 {
		t.Fatalf("ending no session was reported: %+v", events)
	}
	if err := f.a.TerminateSession(t.Context(), first.Principal, "00000000-0000-7000-8000-000000000999", ""); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("TerminateSession = %v", err)
	}
	if events = log.take(); len(events) != 0 {
		t.Fatalf("a session that does not exist was reported: %+v", events)
	}
}

func TestAChangedPasswordIsReported(t *testing.T) {
	f, log := newEventFixture(t)
	login := f.login(t)
	log.take()
	changed, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, "a new password that is long enough 1")
	if err != nil {
		t.Fatal(err)
	}
	events := log.take()
	wantTypes(t, events, EventPasswordChanged, EventSessionEnded)
	if events[0].SessionID != changed.Principal.SessionID || events[0].UserID != string(f.user.ID) || events[1].Details["reason"] != "password_changed" {
		t.Fatalf("events = %+v", events)
	}
	if _, err = f.a.ChangePassword(t.Context(), changed.Principal, "the wrong password", "another new password that is long 2"); err == nil {
		t.Fatal("a wrong current password was accepted")
	}
	if events = log.take(); len(events) != 0 {
		t.Fatalf("a refused change was reported: %+v", events)
	}
}

func TestAReusedRefreshTokenIsReportedTwice(t *testing.T) {
	f, log := newEventFixture(t)
	login := f.tokenLogin(t)
	f.mustRefresh(t, login.Tokens.RefreshToken)
	log.take()
	f.clock.advance(time.Minute)
	f.refused(t, "a stolen token", login.Tokens.RefreshToken)
	events := log.take()
	wantTypes(t, events, EventRefreshTokenReused, EventSessionEnded)
	for _, e := range events {
		if e.UserID != string(f.user.ID) || e.SessionID != login.Principal.SessionID {
			t.Errorf("event = %+v, want the user and the session", e)
		}
	}
	if events[1].Details["reason"] != "refresh_token_reused" {
		t.Errorf("the reason = %q", events[1].Details["reason"])
	}
}

func TestAChangeThatIsRetriedIsReportedOnce(t *testing.T) {
	f, log := newEventFixture(t)
	login := f.login(t)
	log.take()
	stale := &atomic.Int32{}
	stale.Store(2)
	f.a.store = staleOnceStore{Store: f.a.store, stale: stale}
	changed, err := f.a.ChangePassword(t.Context(), login.Principal, goodPassword, newPassword)
	if err != nil {
		t.Fatal(err)
	}
	events := log.take()
	wantTypes(t, events, EventPasswordChanged, EventSessionEnded)
	if events[0].SessionID != changed.Principal.SessionID || events[0].SessionID == "" {
		t.Fatalf("event = %+v, want the session that the change opened", events[0])
	}
}

func TestAHookThatPanicsDoesNotHarmTheOperation(t *testing.T) {
	logger, logs := capturingLogger()
	f := newSessionFixture(t, WithLogger(logger), WithHooks(Hooks{OnEvent: func(context.Context, Event) { panic("the password hunter2 and a token") }}))
	login, err := f.a.Login(t.Context(), f.credentials())
	if err != nil || login.Secret == "" {
		t.Fatalf("Login = %+v, %v; the hook must not break it", login, err)
	}
	if err = f.a.Logout(t.Context(), login.Principal); err != nil {
		t.Fatalf("Logout = %v", err)
	}
	if f.sessionExists(t, login.Principal.SessionID) && f.session(t, login.Principal.SessionID).Session.RevokedAt.IsZero() {
		t.Fatal("the logout was undone")
	}
	text := logs.String()
	if !strings.Contains(text, "the hook of events panicked") || !strings.Contains(text, "panic_type=string") || strings.Contains(text, "hunter2") {
		t.Fatalf("the panic must be logged by its type and not by its value:\n%s", text)
	}
}

func TestAServiceWithoutAHookEmitsNothingAndDoesNotFail(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	if err := f.a.Logout(t.Context(), login.Principal); err != nil {
		t.Fatal(err)
	}
	f.a.emit(t.Context(), Event{Type: EventLogin})
}

func TestEventsHoldNoSecrets(t *testing.T) {
	f, log := newEventFixture(t)
	const wrong = "a wrong password that nobody uses"
	c := f.credentials()
	c.Password = wrong
	_, _ = f.a.Login(t.Context(), c)
	cookie := f.login(t)
	token := f.tokenLogin(t)
	next := f.mustRefresh(t, token.Tokens.RefreshToken)
	changed, err := f.a.ChangePassword(t.Context(), cookie.Principal, goodPassword, "a new password that is long enough 1")
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Minute)
	f.refused(t, "a stolen token", token.Tokens.RefreshToken)
	_ = f.a.Logout(t.Context(), changed.Principal)
	raw, err := json.Marshal(log.take())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		goodPassword, wrong, "a new password that is long enough 1", cookie.Secret, cookie.CSRFToken, changed.Secret, changed.CSRFToken,
		token.Tokens.AccessToken, token.Tokens.RefreshToken, next.AccessToken, next.RefreshToken,
	} {
		if secret != "" && strings.Contains(string(raw), secret) {
			t.Fatalf("the events contain %q: %s", secret, raw)
		}
	}
}

func TestAHookCannotChangeTheDetailsOfTheCaller(t *testing.T) {
	a := newTestAuth(t, WithHooks(Hooks{OnEvent: func(_ context.Context, e Event) { e.Details["added by the hook"] = "yes" }}))
	details := map[string]string{"reason": "test"}
	a.emit(t.Context(), Event{Type: EventLogin, Details: details})
	if len(details) != 1 || details["reason"] != "test" {
		t.Fatalf("the hook changed the details of the caller: %v", details)
	}
}

func TestAFailedMessageIsReportedWithoutItsText(t *testing.T) {
	log := &eventLog{}
	sender := senderFunc(func(_ context.Context, m Message) error {
		return errors.New("rejected " + m.To + " " + m.Code)
	})
	a := newTestAuth(t, WithSender(sender), WithHooks(log.hooks()))
	m := newTestMessage()
	done := make(chan struct{})
	err := a.dispatcher.submit(task{kind: m.Kind, channel: m.Channel, run: func(ctx context.Context) error {
		defer close(done)
		return a.deliver(ctx, m)
	}})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	eventually(t, "the event", func() bool { return len(log.peek()) == 1 })
	e := log.take()[0]
	if e.Type != EventMessageFailed || e.UserID != m.UserID || e.Channel != "email" || e.Address != "a***@example.com" ||
		e.Details["kind"] != "password_reset" || e.Details["reason"] != "rejected" {
		t.Fatalf("event = %+v", e)
	}
	raw, _ := json.Marshal(e)
	for _, secret := range []string{m.Code, m.Link, m.To, testLinkToken} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the event contains %q: %s", secret, raw)
		}
	}
}

func TestAFailureOfAnyOtherKindIsReportedWithTheKindOnly(t *testing.T) {
	log := &eventLog{}
	a := newTestAuth(t, WithSender(&recordingSender{}), WithHooks(log.hooks()))
	for _, run := range []func(ctx context.Context) error{
		func(context.Context) error { return errors.New("the storage failed") },
		func(context.Context) error { panic("boom") },
	} {
		if err := a.dispatcher.submit(task{kind: MessageVerification, channel: "phone", run: run}); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "two events", func() bool { return len(log.peek()) == 2 })
	for _, e := range log.take() {
		if e.Type != EventMessageFailed || e.Channel != "phone" || e.Address != "" || e.UserID != "" ||
			e.Details["kind"] != "verification" || e.Details["reason"] != "failed" {
			t.Fatalf("event = %+v", e)
		}
	}
}

func TestEventAddress(t *testing.T) {
	if got := eventAddress(netip.Addr{}); got != "" {
		t.Fatalf("eventAddress of an invalid address = %q", got)
	}
	if got := eventAddress(netip.MustParseAddr("2001:db8::1")); got != "2001:db8::1" {
		t.Fatalf("eventAddress = %q", got)
	}
}

func (l *eventLog) peek() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}
