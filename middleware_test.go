package limb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

type seen struct {
	calls      int
	principal  Principal
	registered bool
}

func (f *apiFixture) guarded(t *testing.T, wrap func(*Auth, http.Handler) http.Handler) (http.Handler, *seen) {
	t.Helper()
	got := &seen{}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.calls++
		got.principal, got.registered = CurrentUser(r.Context())
		w.WriteHeader(http.StatusTeapot)
	})
	return wrap(f.a, inner), got
}

func requireAuth(a *Auth, next http.Handler) http.Handler  { return a.RequireAuth(next) }
func optionalAuth(a *Auth, next http.Handler) http.Handler { return a.OptionalAuth(next) }

func (f *apiFixture) through(t *testing.T, handler http.Handler, method string, opts ...requestOption) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, appOrigin+"/page", nil)
	for _, opt := range opts {
		opt(r)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	return rec
}

func TestRequireAuthLetsASignedInRequestThrough(t *testing.T) {
	f := newAPIFixture(t)
	handler, got := f.guarded(t, requireAuth)
	login, _ := f.signIn(t)
	tokens, _ := f.signInWithTokens(t)
	tests := []struct {
		name   string
		method string
		opts   []requestOption
		want   Principal
	}{
		{"a cookie reads", http.MethodGet, []requestOption{f.sessionCookie(login.Secret)}, Principal{UserID: f.user.ID, SessionID: login.Principal.SessionID, SessionKind: SessionCookie}},
		{"a cookie writes", http.MethodPost, f.signed(login), Principal{UserID: f.user.ID, SessionID: login.Principal.SessionID, SessionKind: SessionCookie}},
		{"a token reads", http.MethodGet, []requestOption{bearer(tokens.AccessToken)}, Principal{UserID: f.user.ID, SessionID: tokens.SessionID, SessionKind: SessionToken}},
		{"a token writes", http.MethodDelete, []requestOption{bearer(tokens.AccessToken)}, Principal{UserID: f.user.ID, SessionID: tokens.SessionID, SessionKind: SessionToken}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			*got = seen{}
			rec := f.through(t, handler, tc.method, tc.opts...)
			if rec.Code != http.StatusTeapot || got.calls != 1 || !got.registered || got.principal != tc.want {
				t.Fatalf("status = %d, seen = %+v, want the principal %+v", rec.Code, got, tc.want)
			}
		})
	}
}

func TestRequireAuthTurnsDownEveryOtherRequest(t *testing.T) {
	f := newAPIFixture(t)
	handler, got := f.guarded(t, requireAuth)
	login, _ := f.signIn(t)
	tokens, _ := f.signInWithTokens(t)
	tests := []struct {
		name      string
		method    string
		opts      []requestOption
		status    int
		code      string
		challenge string
	}{
		{"nothing", http.MethodGet, nil, http.StatusUnauthorized, "unauthenticated", ""},
		{"a damaged cookie", http.MethodGet, []requestOption{f.sessionCookie("damaged")}, http.StatusUnauthorized, "unauthenticated", ""},
		{"a damaged token", http.MethodGet, []requestOption{bearer("damaged")}, http.StatusUnauthorized, "unauthenticated", `Bearer error="invalid_token"`},
		{"no token after the word", http.MethodGet, []requestOption{header("Authorization", "Bearer")}, http.StatusUnauthorized, "unauthenticated", `Bearer error="invalid_token"`},
		{"a wrong token and a good cookie", http.MethodGet, []requestOption{bearer("damaged"), f.sessionCookie(login.Secret)}, http.StatusUnauthorized, "unauthenticated", `Bearer error="invalid_token"`},
		{"a cookie that writes with no token", http.MethodPost, []requestOption{f.sessionCookie(login.Secret), sameOrigin()}, http.StatusForbidden, "csrf_failed", ""},
		{"a cookie that writes from another site", http.MethodPut, []requestOption{f.sessionCookie(login.Secret), fromOrigin("https://evil.example"), header(csrfHeader, login.CSRFToken)}, http.StatusForbidden, "csrf_failed", ""},
		{"a cookie that writes with no hint", http.MethodDelete, []requestOption{f.sessionCookie(login.Secret), header(csrfHeader, login.CSRFToken)}, http.StatusForbidden, "csrf_failed", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			*got = seen{}
			rec := f.through(t, handler, tc.method, tc.opts...)
			f.expectError(t, rec, tc.status, tc.code)
			if rec.Header().Get("WWW-Authenticate") != tc.challenge || got.calls != 0 {
				t.Fatalf("WWW-Authenticate = %q, calls = %d", rec.Header().Get("WWW-Authenticate"), got.calls)
			}
		})
	}
	f.clock.advance(11 * time.Minute)
	expired := f.through(t, handler, http.MethodGet, bearer(tokens.AccessToken))
	f.expectError(t, expired, http.StatusUnauthorized, "unauthenticated")
	if expired.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("WWW-Authenticate = %q", expired.Header().Get("WWW-Authenticate"))
	}
}

func TestRequireAuthTurnsDownASessionThatEnded(t *testing.T) {
	f := newAPIFixture(t)
	handler, got := f.guarded(t, requireAuth)
	login, _ := f.signIn(t)
	tokens, _ := f.signInWithTokens(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	for name, opts := range map[string][]requestOption{"cookie": {f.sessionCookie(login.Secret)}, "token": {bearer(tokens.AccessToken)}} {
		f.expectError(t, f.through(t, handler, http.MethodGet, opts...), http.StatusUnauthorized, "unauthenticated")
		if got.calls != 0 {
			t.Fatalf("%s: the handler of a blocked user ran", name)
		}
	}
}

func TestRequireAuthClosesEveryRouteToAUserWhoMustChangeThePassword(t *testing.T) {
	f := newAPIFixture(t)
	f.restrict(t)
	handler, got := f.guarded(t, requireAuth)
	login, _ := f.signIn(t)
	tokens, _ := f.signInWithTokens(t)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodDelete} {
		for name, opts := range map[string][]requestOption{"cookie": f.signed(login), "token": {bearer(tokens.AccessToken)}} {
			rec := f.through(t, handler, method, opts...)
			f.expectError(t, rec, http.StatusForbidden, "password_change_required")
			if got.calls != 0 || rec.Header().Get("WWW-Authenticate") != "" {
				t.Fatalf("%s %s: calls = %d, WWW-Authenticate = %q", method, name, got.calls, rec.Header().Get("WWW-Authenticate"))
			}
		}
	}
}

func TestRequireAuthDoesNotTellWhyItFailed(t *testing.T) {
	logger, logs := capturingLogger()
	f := newAPIFixture(t, WithLogger(logger))
	handler, got := f.guarded(t, requireAuth)
	login, _ := f.signIn(t)
	f.breakSessions(func(s *sessionsFault) { s.resolveErr = errors.New(secretReason) })
	rec := f.through(t, handler, http.MethodGet, f.sessionCookie(login.Secret))
	f.expectError(t, rec, http.StatusInternalServerError, "internal_error")
	if strings.Contains(rec.Body.String(), "fire") || strings.Contains(rec.Body.String(), "10.0.0.5") || got.calls != 0 {
		t.Fatalf("the answer tells too much: %s", rec.Body.String())
	}
	if !strings.Contains(logs.String(), secretReason) || !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("the failure is not logged:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), login.Secret) {
		t.Fatal("the secret of the session is in the log")
	}
}

func TestOptionalAuthPutsTheSignedInUserInTheContext(t *testing.T) {
	f := newAPIFixture(t)
	handler, got := f.guarded(t, optionalAuth)
	login, _ := f.signIn(t)
	tokens, _ := f.signInWithTokens(t)
	rec := f.through(t, handler, http.MethodGet, f.sessionCookie(login.Secret))
	if rec.Code != http.StatusTeapot || !got.registered || got.principal.SessionID != login.Principal.SessionID {
		t.Fatalf("seen = %+v", got)
	}
	f.through(t, handler, http.MethodPost, f.signed(login)...)
	if !got.registered || got.principal.SessionID != login.Principal.SessionID {
		t.Fatalf("a write with the CSRF token: seen = %+v", got)
	}
	f.through(t, handler, http.MethodGet, bearer(tokens.AccessToken))
	if !got.registered || got.principal.SessionID != tokens.SessionID || got.principal.SessionKind != SessionToken {
		t.Fatalf("a token: seen = %+v", got)
	}
}

func TestOptionalAuthLetsEveryOtherRequestThroughAsAnonymous(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	tokens, _ := f.signInWithTokens(t)
	tests := []struct {
		name   string
		method string
		opts   []requestOption
	}{
		{"nothing", http.MethodGet, nil},
		{"a damaged cookie", http.MethodGet, []requestOption{f.sessionCookie("damaged")}},
		{"a damaged token", http.MethodGet, []requestOption{bearer("damaged")}},
		{"a wrong token and a good cookie", http.MethodGet, []requestOption{bearer("damaged"), f.sessionCookie(login.Secret)}},
		{"a write that fails the cross-site check", http.MethodPost, []requestOption{f.sessionCookie(login.Secret), fromOrigin("https://evil.example")}},
		{"a write with no token", http.MethodPost, []requestOption{f.sessionCookie(login.Secret), sameOrigin()}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, got := f.guarded(t, optionalAuth)
			rec := f.through(t, handler, tc.method, tc.opts...)
			if rec.Code != http.StatusTeapot || got.calls != 1 || got.registered || got.principal != (Principal{}) {
				t.Fatalf("status = %d, seen = %+v", rec.Code, got)
			}
		})
	}
	f.restrict(t)
	for name, opts := range map[string][]requestOption{"cookie": f.signed(login), "token": {bearer(tokens.AccessToken)}} {
		handler, got := f.guarded(t, optionalAuth)
		if rec := f.through(t, handler, http.MethodGet, opts...); rec.Code != http.StatusTeapot || got.registered {
			t.Fatalf("%s of a user who must change the password: status = %d, seen = %+v", name, rec.Code, got)
		}
	}
}

func TestOptionalAuthLogsAFailureToReadTheSessionAndGoesOnAnonymous(t *testing.T) {
	logger, logs := capturingLogger()
	f := newAPIFixture(t, WithLogger(logger))
	handler, got := f.guarded(t, optionalAuth)
	login, _ := f.signIn(t)
	f.breakSessions(func(s *sessionsFault) { s.resolveErr = errors.New(secretReason) })
	rec := f.through(t, handler, http.MethodGet, f.sessionCookie(login.Secret))
	if rec.Code != http.StatusTeapot || got.registered {
		t.Fatalf("status = %d, seen = %+v", rec.Code, got)
	}
	if !strings.Contains(logs.String(), secretReason) || !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("the failure is not logged:\n%s", logs.String())
	}
}

func TestOptionalAuthSaysNothingAboutAnOrdinaryFailure(t *testing.T) {
	logger, logs := capturingLogger()
	f := newAPIFixture(t, WithLogger(logger))
	handler, _ := f.guarded(t, optionalAuth)
	login, _ := f.signIn(t)
	f.through(t, handler, http.MethodGet, bearer("damaged"))
	f.through(t, handler, http.MethodGet)
	f.through(t, handler, http.MethodPost, f.sessionCookie(login.Secret), sameOrigin())
	f.restrict(t)
	f.through(t, handler, http.MethodGet, f.sessionCookie(login.Secret))
	if strings.Contains(logs.String(), "level=ERROR") || strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("an anonymous request is logged as a failure:\n%s", logs.String())
	}
}

func TestCurrentUserOfAContextThatNoMiddlewareTouchedIsNobody(t *testing.T) {
	if principal, ok := CurrentUser(t.Context()); ok || principal != (Principal{}) {
		t.Fatalf("CurrentUser = %+v, %v", principal, ok)
	}
}

func TestARequestThatWasCancelledIsNotLoggedAsAnError(t *testing.T) {
	logger, logs := capturingLogger()
	f := newAPIFixture(t, WithLogger(logger))
	handler, _ := f.guarded(t, requireAuth)
	login, _ := f.signIn(t)
	f.breakSessions(func(s *sessionsFault) { s.resolveErr = fmt.Errorf("read the session: %w", context.Canceled) })
	rec := f.through(t, handler, http.MethodGet, f.sessionCookie(login.Secret))
	f.expectError(t, rec, http.StatusInternalServerError, "internal_error")
	if strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "level=DEBUG") {
		t.Fatalf("a cancelled request must be logged below the errors:\n%s", logs.String())
	}
}
