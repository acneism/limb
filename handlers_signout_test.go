package limb

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogoutEndsACookieSessionAndClearsItsCookie(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	rec := f.send(t, http.MethodPost, "/logout", nil, f.signed(login)...)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("POST /logout = %d: %s", rec.Code, rec.Body.String())
	}
	requireCleared(t, rec, f.a.cookie, "/")
	if cleared := cookieNamed(rec, f.a.cookie); !cleared.Secure || cleared.SameSite != http.SameSiteLaxMode {
		t.Fatalf("the cookie that clears must carry the attributes of the one that was set: %+v", cleared)
	}
	if f.sessionWorks(t, login.Principal.SessionID) {
		t.Fatal("the session must end")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestLogoutIsTheSameWhenThereIsNothingToEnd(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	first := f.send(t, http.MethodPost, "/logout", nil, f.signed(login)...)
	if first.Code != http.StatusNoContent {
		t.Fatalf("the first POST /logout = %d", first.Code)
	}
	answers := map[string]*httptest.ResponseRecorder{
		"again":      f.send(t, http.MethodPost, "/logout", nil, f.signed(login)...),
		"nothing":    f.send(t, http.MethodPost, "/logout", nil),
		"damaged":    f.send(t, http.MethodPost, "/logout", nil, f.sessionCookie("damaged"), sameOrigin()),
		"bad bearer": f.send(t, http.MethodPost, "/logout", nil, bearer("not a token")),
	}
	for name, rec := range answers {
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Errorf("%s: POST /logout = %d: %s", name, rec.Code, rec.Body.String())
		}
		requireCleared(t, rec, f.a.cookie, "/")
	}
}

func TestLogoutNeedsTheCrossSiteCheckForACookieSession(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	tests := map[string][]requestOption{
		"no hint":           {f.sessionCookie(login.Secret)},
		"no token":          {f.sessionCookie(login.Secret), sameOrigin()},
		"a wrong token":     {f.sessionCookie(login.Secret), sameOrigin(), header(csrfHeader, f.a.keys.CSRFToken("another session"))},
		"another origin":    {f.sessionCookie(login.Secret), fromOrigin("https://evil.example"), header(csrfHeader, login.CSRFToken)},
		"a token of a form": {f.sessionCookie(login.Secret), sameOrigin(), header(csrfHeader, login.CSRFToken+"=")},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			rec := f.send(t, http.MethodPost, "/logout", nil, opts...)
			f.expectError(t, rec, http.StatusForbidden, "csrf_failed")
			if rec.Header().Get("Set-Cookie") != "" {
				t.Fatal("a refused sign-out changes the cookie")
			}
			if !f.sessionWorks(t, login.Principal.SessionID) {
				t.Fatal("a refused sign-out must not end the session")
			}
		})
	}
}

func TestLogoutOfATokenSessionNeedsNoCSRFToken(t *testing.T) {
	f := newAPIFixture(t)
	body, _ := f.signInWithTokens(t)
	rec := f.send(t, http.MethodPost, "/logout", nil, bearer(body.AccessToken))
	if rec.Code != http.StatusNoContent || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("POST /logout = %d, Set-Cookie = %v", rec.Code, rec.Header()["Set-Cookie"])
	}
	if f.sessionWorks(t, body.SessionID) {
		t.Fatal("the session must end")
	}
	if err := f.bearerError(t, body.AccessToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("the access token of the session that ended = %v", err)
	}
	refreshed := f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": body.RefreshToken})
	f.expectError(t, refreshed, http.StatusUnauthorized, "unauthenticated")
}

func TestLogoutDoesNotTouchTheCookieSessionOfABearerRequest(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	body, _ := f.signInWithTokens(t)
	rec := f.send(t, http.MethodPost, "/logout", nil, bearer(body.AccessToken), f.sessionCookie(login.Secret))
	if rec.Code != http.StatusNoContent || cookieNamed(rec, f.a.cookie) != nil {
		t.Fatalf("POST /logout = %d, cookies = %v", rec.Code, rec.Header()["Set-Cookie"])
	}
	if !f.sessionWorks(t, login.Principal.SessionID) || f.sessionWorks(t, body.SessionID) {
		t.Fatal("only the session of the token may end")
	}
}

func TestAUserWhoMustChangeThePasswordCanStillSignOut(t *testing.T) {
	f := newAPIFixture(t)
	f.restrict(t)
	login, _ := f.signIn(t)
	body, _ := f.signInWithTokens(t)
	for name, opts := range map[string][]requestOption{"cookie": f.signed(login), "token": {bearer(body.AccessToken)}} {
		t.Run(name, func(t *testing.T) {
			if rec := f.send(t, http.MethodPost, "/logout", nil, opts...); rec.Code != http.StatusNoContent {
				t.Fatalf("POST /logout = %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
	if f.sessionWorks(t, login.Principal.SessionID) || f.sessionWorks(t, body.SessionID) {
		t.Fatal("both sessions must end")
	}
}

func TestLogoutDoesNotPretendToHaveEndedASessionThatItCouldNotEnd(t *testing.T) {
	logger, logs := capturingLogger()
	f := newAPIFixture(t, WithLogger(logger))
	login, _ := f.signIn(t)
	f.breakSessions(func(s *sessionsFault) { s.revokeErr = errors.New(secretReason) })
	rec := f.send(t, http.MethodPost, "/logout", nil, f.signed(login)...)
	f.expectError(t, rec, http.StatusInternalServerError, "internal_error")
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("the cookie of a session that is still alive was cleared: %v", got)
	}
	if strings.Contains(rec.Body.String(), "fire") || !strings.Contains(logs.String(), secretReason) {
		t.Fatalf("body = %s\nlog = %s", rec.Body.String(), logs.String())
	}
	if !f.sessionWorks(t, login.Principal.SessionID) {
		t.Fatal("the session must go on")
	}
}
