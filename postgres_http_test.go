package limb

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func newPostgresAPI(t *testing.T) (*apiFixture, *apiFixture) {
	t.Helper()
	in := newInstances(t)
	user := mustRegister(t, in.a, map[string]string{"email": "nina@example.com", "username": "nina_n"}, goodPassword)
	build := func(a *Auth) *apiFixture {
		shared := &sessionFixture{fixture: &fixture{a: a, user: user}, clock: in.clock}
		return &apiFixture{sessionFixture: shared, handler: a.Handler()}
	}
	return build(in.a), build(in.b)
}

func TestPostgresTheHTTPAPIIsSharedBetweenInstances(t *testing.T) {
	a, b := newPostgresAPI(t)
	login, _ := a.signIn(t)
	rec := b.send(t, http.MethodGet, "/sessions/current", nil, b.sessionCookie(login.Secret))
	if rec.Code != http.StatusOK || decodeBody[currentSessionBody](t, rec).CSRFToken != login.CSRFToken {
		t.Fatalf("another instance does not know the session: %d %s", rec.Code, rec.Body.String())
	}
	tokens, _ := b.signInWithTokens(t)
	listed := a.send(t, http.MethodGet, "/sessions", nil, bearer(tokens.AccessToken))
	if listed.Code != http.StatusOK || len(decodeBody[sessionsBody](t, listed).Sessions) != 2 {
		t.Fatalf("GET /sessions = %d: %s", listed.Code, listed.Body.String())
	}
	a.clock.advance(time.Minute)
	refreshed := a.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": tokens.RefreshToken})
	if refreshed.Code != http.StatusOK {
		t.Fatalf("POST /token/refresh = %d: %s", refreshed.Code, refreshed.Body.String())
	}
	b.expectError(t, b.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": tokens.RefreshToken}), http.StatusUnauthorized, "unauthenticated")
	if out := b.send(t, http.MethodPost, "/logout", nil, b.signed(login)...); out.Code != http.StatusNoContent {
		t.Fatalf("POST /logout = %d: %s", out.Code, out.Body.String())
	}
	a.expectError(t, a.send(t, http.MethodGet, "/sessions/current", nil, a.sessionCookie(login.Secret)), http.StatusUnauthorized, "unauthenticated")
}

func TestPostgresBothInstancesPublishTheSameKeys(t *testing.T) {
	a, b := newPostgresAPI(t)
	first, second := a.publishedKeys(t), b.publishedKeys(t)
	if len(first) != 1 || len(second) != 1 || first[0]["kid"] != second[0]["kid"] || first[0]["x"] != second[0]["x"] {
		t.Fatalf("keys: %v and %v", first, second)
	}
	tokens, _ := a.signInWithTokens(t)
	if rec := b.send(t, http.MethodGet, "/sessions", nil, bearer(tokens.AccessToken)); rec.Code != http.StatusOK {
		t.Fatalf("the other instance does not accept the token: %d", rec.Code)
	}
}

func TestPostgresDeleteSessionAnswersNotFoundForAnyID(t *testing.T) {
	a, _ := newPostgresAPI(t)
	login, _ := a.signIn(t)
	ids := []string{
		"%00", "a%00b", "%ff", "%ff%fe", "%c0%af", "%ed%a0%80", "current", strings.Repeat("a", 5000), "%F0%9F%98%80",
		"0000%2f0000", "%27%20OR%20%271%27=%271", "%25", "00000000-0000-7000-8000-00000000dead",
	}
	for _, id := range ids {
		rec := a.send(t, http.MethodDelete, "/sessions/"+id, nil, a.signed(login)...)
		if rec.Code != http.StatusNotFound {
			t.Errorf("DELETE /sessions/%.40s = %d: %s", id, rec.Code, rec.Body.String())
		}
	}
	if !a.sessionWorks(t, login.Principal.SessionID) {
		t.Fatal("the session must go on")
	}
}

func TestPostgresOddInputsNeverBreakTheAPI(t *testing.T) {
	a, _ := newPostgresAPI(t)
	login, _ := a.signIn(t)
	odd := []string{`a\u0000b`, `\u0000`, `\ud800`, `�`, strings.Repeat("x", 3000), strings.Repeat(`\u0000`, 500)}
	cookie := a.a.cookie + "=" + "a\x00b"
	for _, value := range odd {
		body := `{"login":"` + value + `","password":"` + goodPassword + `"}`
		for _, path := range []string{"/login", "/token"} {
			if rec := a.send(t, http.MethodPost, path, body, sameOrigin()); rec.Code >= http.StatusInternalServerError {
				t.Errorf("POST %s with the login %.30q = %d: %s", path, value, rec.Code, rec.Body.String())
			}
		}
		refresh := `{"refresh_token":"` + value + `"}`
		if rec := a.send(t, http.MethodPost, "/token/refresh", refresh); rec.Code != http.StatusUnauthorized {
			t.Errorf("POST /token/refresh with the token %.30q = %d: %s", value, rec.Code, rec.Body.String())
		}
		change := `{"current_password":"` + value + `","new_password":"` + value + `"}`
		if rec := a.send(t, http.MethodPost, "/password/change", change, a.signed(login)...); rec.Code >= http.StatusInternalServerError {
			t.Errorf("POST /password/change with %.30q = %d: %s", value, rec.Code, rec.Body.String())
		}
	}
	for _, opts := range [][]requestOption{
		{header("Cookie", cookie)},
		{bearer("a\x00b")},
		{header("Authorization", "Bearer \xff\xfe")},
	} {
		if rec := a.send(t, http.MethodGet, "/sessions", nil, opts...); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET /sessions with odd credentials = %d: %s", rec.Code, rec.Body.String())
		}
	}
	if !a.sessionWorks(t, login.Principal.SessionID) || !a.canSignInWith(t, goodPassword) {
		t.Fatal("nothing may change")
	}
}
