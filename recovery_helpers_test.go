package limb

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/store"
)

type recoveryFixture struct {
	a      *Auth
	clock  *fakeClock
	sender *recordingSender
	events *eventLog
	user   User
}

func smsType() identifier.Type {
	return identifier.Custom("sms", identifier.Pattern(`\+[0-9]{10,14}`), identifier.Delivery())
}

func newRecoveryFixture(t *testing.T, opts ...Option) *recoveryFixture {
	t.Helper()
	sender := &recordingSender{}
	events := &eventLog{}
	all := append([]Option{
		WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username(), smsType()),
		WithSender(sender),
		WithHooks(events.hooks()),
		WithVerifyURL("https://app.example.com/verify"),
		WithResetURL("https://app.example.com/reset"),
		WithServiceName("Acme"),
	}, opts...)
	a, clock := newLimitedAuth(t, all...)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})
	user := mustRegister(t, a, map[string]string{"email": "Nina@Example.com", "username": "nina_n"}, goodPassword)
	events.take()
	return &recoveryFixture{a: a, clock: clock, sender: sender, events: events, user: user}
}

func (f *recoveryFixture) idle(t *testing.T) {
	t.Helper()
	eventually(t, "the queue of messages to empty", func() bool { return f.a.dispatcher.pending.Load() == 0 })
}

func (f *recoveryFixture) messages(t *testing.T, n int) []Message {
	t.Helper()
	eventually(t, "the messages to be sent", func() bool { return len(f.sender.sent()) >= n })
	f.idle(t)
	got := f.sender.sent()
	if len(got) != n {
		t.Fatalf("%d messages were sent, want %d: %+v", len(got), n, got)
	}
	return got
}

func (f *recoveryFixture) noMessages(t *testing.T) {
	t.Helper()
	f.idle(t)
	if got := f.sender.sent(); len(got) != 0 {
		t.Fatalf("messages were sent, want none: %+v", got)
	}
}

func (f *recoveryFixture) verify(t *testing.T, typ, value string) {
	t.Helper()
	if err := f.a.store.Identifiers().MarkVerified(t.Context(), f.a.tenant, typ, value, f.clock.now().UTC()); err != nil {
		t.Fatal(err)
	}
}

const ninaPhone = "+79991234567"

func (f *recoveryFixture) addPhone(t *testing.T) {
	t.Helper()
	err := f.a.store.Identifiers().Add(t.Context(), store.Identifier{
		TenantID: f.a.tenant, Type: "sms", Value: ninaPhone, DisplayValue: ninaPhone, UserID: string(f.user.ID),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *recoveryFixture) identifierOf(t *testing.T, typ string) store.Identifier {
	t.Helper()
	list, err := f.a.store.Identifiers().ListByUser(t.Context(), f.a.tenant, string(f.user.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range list {
		if i.Type == typ {
			return i
		}
	}
	t.Fatalf("the user has no %s identifier", typ)
	return store.Identifier{}
}

func (f *recoveryFixture) takeEvents(t *testing.T, n int) []Event {
	t.Helper()
	eventually(t, "the events to reach the hook", func() bool { return len(f.events.peek()) >= n })
	return f.events.take()
}

func (f *recoveryFixture) change(t *testing.T, edit func(*store.User)) {
	t.Helper()
	u, err := f.a.store.Users().Get(t.Context(), f.a.tenant, string(f.user.ID))
	if err != nil {
		t.Fatal(err)
	}
	edit(&u)
	if _, err = f.a.store.Users().Update(t.Context(), u); err != nil {
		t.Fatal(err)
	}
}

func (f *recoveryFixture) block(t *testing.T) (release func()) {
	t.Helper()
	started := make(chan struct{})
	gate := make(chan struct{})
	err := f.a.dispatcher.submit(task{kind: MessageVerification, run: func(context.Context) error {
		close(started)
		<-gate
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	return release
}

func tokenOf(link string) string {
	_, token, _ := strings.Cut(link, "#token=")
	return token
}

type accessLog struct {
	store.Store
	mu    sync.Mutex
	names []string
}

func (s *accessLog) note(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names = append(s.names, name)
}

func (s *accessLog) taken() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.names...)
}

func (s *accessLog) Users() store.Users {
	s.note("users")
	return s.Store.Users()
}

func (s *accessLog) Identifiers() store.Identifiers {
	s.note("identifiers")
	return s.Store.Identifiers()
}

func (s *accessLog) Sessions() store.Sessions {
	s.note("sessions")
	return s.Store.Sessions()
}

func (s *accessLog) RefreshTokens() store.RefreshTokens {
	s.note("refresh tokens")
	return s.Store.RefreshTokens()
}

func (s *accessLog) Secrets() store.Secrets {
	s.note("secrets")
	return s.Store.Secrets()
}

func (s *accessLog) Attempts() store.Attempts {
	s.note("attempts")
	return s.Store.Attempts()
}

func (s *accessLog) SigningKeys() store.SigningKeys {
	s.note("signing keys")
	return s.Store.SigningKeys()
}

func (s *accessLog) InTx(ctx context.Context, fn func(ctx context.Context, tx store.Repositories) error) error {
	s.note("transaction")
	return s.Store.InTx(ctx, fn)
}
