package limb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/store"
)

const testAgent = "Mozilla/5.0 (X11; Linux x86_64) limb-test"

var testIP = netip.MustParseAddr("203.0.113.7")

type sessionFixture struct {
	*fixture
	clock *fakeClock
}

func newSessionFixture(t *testing.T, opts ...Option) *sessionFixture {
	t.Helper()
	f := newFixture(t, opts...)
	clock := newFakeClock()
	f.a.now = clock.now
	return &sessionFixture{fixture: f, clock: clock}
}

func (f *sessionFixture) credentials() Credentials {
	return Credentials{Login: "nina@example.com", Password: goodPassword, IP: testIP, UserAgent: testAgent, Kind: SessionCookie}
}

func (f *sessionFixture) login(t *testing.T) Login {
	t.Helper()
	login, err := f.a.Login(t.Context(), f.credentials())
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	return login
}

func (f *sessionFixture) session(t *testing.T, id string) store.ResolvedSession {
	t.Helper()
	resolved, err := f.a.store.Sessions().ResolveByID(t.Context(), f.a.tenant, id)
	if err != nil {
		t.Fatalf("ResolveByID(%s) failed: %v", id, err)
	}
	return resolved
}

func (f *sessionFixture) request(t *testing.T, method string, login Login, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, "http://app.example.com/api", nil)
	r.Header.Set("Cookie", f.a.cookie+"="+login.Secret)
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	return r
}

func (f *sessionFixture) sessionExists(t *testing.T, id string) bool {
	t.Helper()
	_, err := f.a.store.Sessions().ResolveByID(t.Context(), f.a.tenant, id)
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		return false
	}
	t.Fatal(err)
	return false
}

func (f *sessionFixture) sameOrigin(login Login) map[string]string {
	return map[string]string{"Sec-Fetch-Site": "same-origin", csrfHeader: login.CSRFToken}
}

type sessionsFault struct {
	store.Sessions
	createErr, resolveErr, touchErr, revokeErr, listErr error
	touched                                             *[]string
}

func (s sessionsFault) Create(ctx context.Context, sess store.Session) error {
	if s.createErr != nil {
		return s.createErr
	}
	return s.Sessions.Create(ctx, sess)
}

func (s sessionsFault) ResolveBySecret(ctx context.Context, tenantID string, hash []byte) (store.ResolvedSession, error) {
	if s.resolveErr != nil {
		return store.ResolvedSession{}, s.resolveErr
	}
	return s.Sessions.ResolveBySecret(ctx, tenantID, hash)
}

func (s sessionsFault) ResolveByID(ctx context.Context, tenantID, id string) (store.ResolvedSession, error) {
	if s.resolveErr != nil {
		return store.ResolvedSession{}, s.resolveErr
	}
	return s.Sessions.ResolveByID(ctx, tenantID, id)
}

func (s sessionsFault) Touch(ctx context.Context, tenantID, id string, at time.Time) error {
	if s.touched != nil {
		*s.touched = append(*s.touched, id)
	}
	if s.touchErr != nil {
		return s.touchErr
	}
	return s.Sessions.Touch(ctx, tenantID, id, at)
}

func (s sessionsFault) Revoke(ctx context.Context, tenantID, userID, id string, at time.Time) error {
	if s.revokeErr != nil {
		return s.revokeErr
	}
	return s.Sessions.Revoke(ctx, tenantID, userID, id, at)
}

func (s sessionsFault) ListByUser(ctx context.Context, tenantID, userID string, now time.Time) ([]store.Session, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.Sessions.ListByUser(ctx, tenantID, userID, now)
}

type sessionsFaultStore struct {
	store.Store
	fault sessionsFault
}

func (s *sessionsFaultStore) Sessions() store.Sessions {
	return s.fault
}

func (f *sessionFixture) breakSessions(edit func(*sessionsFault)) {
	fault := sessionsFault{Sessions: f.a.store.Sessions()}
	edit(&fault)
	f.a.store = &sessionsFaultStore{Store: f.a.store, fault: fault}
}

func newFixtureErr(t *testing.T, opts ...Option) error {
	t.Helper()
	_, err := NewWithStore(newTestMemory(), []byte(testKey), append([]Option{WithAutoMigrate()}, opts...)...)
	return err
}

func newTestMemory() store.Store {
	return memstore.New()
}
