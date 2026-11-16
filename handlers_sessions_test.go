package limb

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLogoutAllEndsEverySessionOfTheUser(t *testing.T) {
	f := newAPIFixture(t)
	mustRegister(t, f.a, map[string]string{"email": "omar@example.com", "username": "omar_o"}, goodPassword)
	mine, _ := f.signIn(t)
	other := f.login(t)
	tokens, _ := f.signInWithTokens(t)
	stranger, err := f.a.Login(t.Context(), Credentials{Login: "omar@example.com", Password: goodPassword, Kind: SessionCookie})
	if err != nil {
		t.Fatal(err)
	}
	rec := f.send(t, http.MethodPost, "/logout/all", nil, f.signed(mine)...)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("POST /logout/all = %d: %s", rec.Code, rec.Body.String())
	}
	requireCleared(t, rec, f.a.cookie, "/")
	for _, id := range []string{mine.Principal.SessionID, other.Principal.SessionID, tokens.SessionID} {
		if f.sessionWorks(t, id) {
			t.Fatalf("the session %s must end", id)
		}
	}
	if !f.sessionWorks(t, stranger.Principal.SessionID) {
		t.Fatal("the session of another user must go on")
	}
}

func TestLogoutAllOfATokenSessionClearsTheRefreshCookie(t *testing.T) {
	f := newRefreshCookieFixture(t)
	body, _ := f.cookieSignIn(t)
	rec := f.send(t, http.MethodPost, "/logout/all", nil, bearer(body.AccessToken))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST /logout/all = %d: %s", rec.Code, rec.Body.String())
	}
	requireCleared(t, rec, f.a.refreshCookie, "/auth/token/refresh")
	if cookieNamed(rec, f.a.cookie) != nil {
		t.Fatal("the cookie of a cookie session must stay")
	}
}

func TestLogoutAllWithoutThePasswordOptionIgnoresThePassword(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	rec := f.send(t, http.MethodPost, "/logout/all", map[string]string{"password": "whatever it is"}, f.signed(login)...)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST /logout/all = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLogoutAllReadsOnlyAWellFormedBody(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	tests := []struct {
		name string
		body any
		opts []requestOption
		want int
		code string
	}{
		{"an unknown field", `{"password":"x","all":true}`, nil, http.StatusBadRequest, "invalid_request"},
		{"not JSON", `password`, nil, http.StatusBadRequest, "invalid_request"},
		{"a form", `password=x`, []requestOption{header("Content-Type", "application/x-www-form-urlencoded")}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := append(f.signed(login), tc.opts...)
			f.expectError(t, f.send(t, http.MethodPost, "/logout/all", tc.body, opts...), tc.want, tc.code)
			if !f.sessionWorks(t, login.Principal.SessionID) {
				t.Fatal("a refused request must not end the session")
			}
		})
	}
}

func TestEndingSessionsCanAskForThePassword(t *testing.T) {
	f := newAPIFixture(t, WithPasswordToEndSessions())
	mine, _ := f.signIn(t)
	other := f.login(t)
	signed := f.signed(mine)
	for name, tc := range map[string]struct {
		method, path string
		body         any
	}{
		"logout all":      {http.MethodPost, "/logout/all", nil},
		"end another one": {http.MethodDelete, "/sessions/" + other.Principal.SessionID, nil},
	} {
		t.Run(name, func(t *testing.T) {
			f.expectError(t, f.send(t, tc.method, tc.path, tc.body, signed...), http.StatusBadRequest, "invalid_request")
			f.expectError(t, f.send(t, tc.method, tc.path, map[string]string{"password": ""}, signed...), http.StatusBadRequest, "invalid_request")
			f.expectError(t, f.send(t, tc.method, tc.path, map[string]string{"password": "not the password at all"}, signed...), http.StatusUnauthorized, "invalid_credentials")
			if !f.sessionWorks(t, mine.Principal.SessionID) || !f.sessionWorks(t, other.Principal.SessionID) {
				t.Fatal("a refused request must not end a session")
			}
		})
	}
	if rec := f.send(t, http.MethodDelete, "/sessions/"+other.Principal.SessionID, map[string]string{"password": goodPassword}, signed...); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /sessions/{id} with the password = %d: %s", rec.Code, rec.Body.String())
	}
	if f.sessionWorks(t, other.Principal.SessionID) || !f.sessionWorks(t, mine.Principal.SessionID) {
		t.Fatal("only the other session must end")
	}
	if rec := f.send(t, http.MethodPost, "/logout/all", map[string]string{"password": goodPassword}, signed...); rec.Code != http.StatusNoContent {
		t.Fatalf("POST /logout/all with the password = %d: %s", rec.Code, rec.Body.String())
	}
	if f.sessionWorks(t, mine.Principal.SessionID) {
		t.Fatal("every session must end")
	}
}

func TestEndingTheCurrentSessionNeverAsksForThePassword(t *testing.T) {
	f := newAPIFixture(t, WithPasswordToEndSessions())
	mine, _ := f.signIn(t)
	rec := f.send(t, http.MethodDelete, "/sessions/"+mine.Principal.SessionID, nil, f.signed(mine)...)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /sessions/{current id} = %d: %s", rec.Code, rec.Body.String())
	}
	requireCleared(t, rec, f.a.cookie, "/")
	if f.sessionWorks(t, mine.Principal.SessionID) {
		t.Fatal("the session must end")
	}
}

func TestTheWrongPasswordToEndSessionsIsLimited(t *testing.T) {
	f := newAPIFixture(t, WithPasswordToEndSessions())
	login, _ := f.signIn(t)
	wrong := map[string]string{"password": "not the password at all"}
	for range 20 {
		f.send(t, http.MethodPost, "/logout/all", wrong, f.signed(login)...)
	}
	rec := f.send(t, http.MethodPost, "/logout/all", map[string]string{"password": goodPassword}, f.signed(login)...)
	f.expectError(t, rec, http.StatusTooManyRequests, "rate_limited")
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q", got)
	}
	if !f.sessionWorks(t, login.Principal.SessionID) {
		t.Fatal("a limited request must not end the session")
	}
}

func TestSessionsListsTheSessionsOfTheUser(t *testing.T) {
	f := newAPIFixture(t)
	mine, _ := f.signIn(t)
	f.clock.advance(time.Hour)
	tokens, _ := f.signInWithTokens(t)
	rec := f.send(t, http.MethodGet, "/sessions", nil, f.signed(mine)...)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /sessions = %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody[sessionsBody](t, rec)
	if len(body.Sessions) != 2 {
		t.Fatalf("sessions = %+v", body.Sessions)
	}
	first, second := body.Sessions[0], body.Sessions[1]
	if first.ID != mine.Principal.SessionID || !first.Current || first.Kind != SessionCookie || first.UserAgent != testAgent || first.IP != "192.0.2.1" {
		t.Fatalf("first = %+v", first)
	}
	if second.ID != tokens.SessionID || second.Current || second.Kind != SessionToken || !second.CreatedAt.After(first.CreatedAt) {
		t.Fatalf("second = %+v", second)
	}
	if want := f.clock.now().Add(-time.Hour).Add(30 * 24 * time.Hour).UTC().Truncate(time.Second); !first.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", first.ExpiresAt, want)
	}
	if want := f.clock.now().Add(-time.Hour).UTC().Truncate(time.Second); !first.CreatedAt.Equal(want) || !second.CreatedAt.Equal(f.clock.now().UTC().Truncate(time.Second)) {
		t.Fatalf("created_at = %v and %v, want %v and the present", first.CreatedAt, second.CreatedAt, want)
	}
	if want := f.clock.now().UTC().Truncate(time.Second); !first.LastSeenAt.Equal(want) || !second.LastSeenAt.Equal(want) {
		t.Fatalf("last_seen_at = %v and %v, want %v", first.LastSeenAt, second.LastSeenAt, want)
	}
	asToken := decodeBody[sessionsBody](t, f.send(t, http.MethodGet, "/sessions", nil, bearer(tokens.AccessToken)))
	if len(asToken.Sessions) != 2 || asToken.Sessions[0].Current || !asToken.Sessions[1].Current {
		t.Fatalf("as the token session: %+v", asToken.Sessions)
	}
	if strings.Contains(rec.Body.String(), mine.Secret) || strings.Contains(rec.Body.String(), mine.CSRFToken) {
		t.Fatal("a secret is in the list")
	}
}

func TestSessionsAreNotSeenWithoutASession(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	rec := f.send(t, http.MethodGet, "/sessions", nil)
	f.expectError(t, rec, http.StatusUnauthorized, "unauthenticated")
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("WWW-Authenticate = %q for a request without a Bearer token", rec.Header().Get("WWW-Authenticate"))
	}
	f.expectError(t, f.send(t, http.MethodGet, "/sessions", nil, f.sessionCookie("damaged")), http.StatusUnauthorized, "unauthenticated")
	bad := f.send(t, http.MethodGet, "/sessions", nil, bearer("damaged"), f.sessionCookie(login.Secret))
	f.expectError(t, bad, http.StatusUnauthorized, "unauthenticated")
	if got := bad.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestTheCurrentSessionOfACookieSessionCarriesItsCSRFToken(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	rec := f.send(t, http.MethodGet, "/sessions/current", nil, f.sessionCookie(login.Secret))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET /sessions/current = %d, Cache-Control = %q: %s", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	body := decodeBody[currentSessionBody](t, rec)
	if body.UserID != string(f.user.ID) || body.SessionID != login.Principal.SessionID || body.Kind != SessionCookie || body.PasswordChangeRequired {
		t.Fatalf("body = %+v", body)
	}
	if body.CSRFToken != login.CSRFToken || !f.a.keys.CheckCSRF(body.SessionID, body.CSRFToken) {
		t.Fatalf("csrf_token = %q, want %q", body.CSRFToken, login.CSRFToken)
	}
	if want := f.clock.now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second); !body.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", body.ExpiresAt, want)
	}
	again := f.send(t, http.MethodPost, "/logout", nil, f.sessionCookie(login.Secret), sameOrigin(), header(csrfHeader, body.CSRFToken))
	if again.Code != http.StatusNoContent {
		t.Fatalf("the CSRF token that was read does not work: %d", again.Code)
	}
}

func TestTheCurrentSessionOfATokenSessionHasNoCSRFToken(t *testing.T) {
	f := newAPIFixture(t)
	tokens, _ := f.signInWithTokens(t)
	rec := f.send(t, http.MethodGet, "/sessions/current", nil, bearer(tokens.AccessToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /sessions/current = %d: %s", rec.Code, rec.Body.String())
	}
	if _, found := decodeMap(t, rec)["csrf_token"]; found {
		t.Fatal("a token session has no CSRF token")
	}
	if body := decodeBody[currentSessionBody](t, rec); body.SessionID != tokens.SessionID || body.Kind != SessionToken {
		t.Fatalf("body = %+v", body)
	}
}

func TestTheCurrentSessionIsAnsweredToAUserWhoMustChangeThePassword(t *testing.T) {
	f := newAPIFixture(t)
	f.restrict(t)
	login, _ := f.signIn(t)
	tokens, _ := f.signInWithTokens(t)
	for name, opts := range map[string][]requestOption{"cookie": {f.sessionCookie(login.Secret)}, "token": {bearer(tokens.AccessToken)}} {
		t.Run(name, func(t *testing.T) {
			rec := f.send(t, http.MethodGet, "/sessions/current", nil, opts...)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /sessions/current = %d: %s", rec.Code, rec.Body.String())
			}
			if body := decodeBody[currentSessionBody](t, rec); !body.PasswordChangeRequired {
				t.Fatalf("body = %+v", body)
			}
		})
	}
}

func TestTheCurrentSessionIsNotAnsweredWithoutASession(t *testing.T) {
	f := newAPIFixture(t)
	f.expectError(t, f.send(t, http.MethodGet, "/sessions/current", nil), http.StatusUnauthorized, "unauthenticated")
	f.expectError(t, f.send(t, http.MethodGet, "/sessions/current", nil, bearer("damaged")), http.StatusUnauthorized, "unauthenticated")
}

func TestEverythingElseIsClosedToAUserWhoMustChangeThePassword(t *testing.T) {
	f := newServicesAPIFixture(t)
	f.restrict(t)
	login, _ := f.signIn(t)
	tokens, _ := f.signInWithTokens(t)
	other := f.login(t)
	closed := []struct{ method, path string }{
		{http.MethodGet, "/sessions"},
		{http.MethodDelete, "/sessions/" + other.Principal.SessionID},
		{http.MethodPost, "/logout/all"},
	}
	for _, route := range closed {
		for name, opts := range map[string][]requestOption{"cookie": f.signed(login), "token": {bearer(tokens.AccessToken)}} {
			rec := f.send(t, route.method, route.path, nil, opts...)
			f.expectError(t, rec, http.StatusForbidden, "password_change_required")
			if rec.Header().Get("WWW-Authenticate") != "" {
				t.Errorf("%s %s (%s): WWW-Authenticate = %q", route.method, route.path, name, rec.Header().Get("WWW-Authenticate"))
			}
		}
	}
	for _, id := range []string{login.Principal.SessionID, tokens.SessionID, other.Principal.SessionID} {
		if !f.sessionWorks(t, id) {
			t.Fatalf("the session %s must go on", id)
		}
	}
}

func TestEndSessionEndsAnotherSessionOfTheUser(t *testing.T) {
	f := newAPIFixture(t)
	mine, _ := f.signIn(t)
	other := f.login(t)
	rec := f.send(t, http.MethodDelete, "/sessions/"+other.Principal.SessionID, nil, f.signed(mine)...)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("DELETE /sessions/{id} = %d, Set-Cookie = %v: %s", rec.Code, rec.Header()["Set-Cookie"], rec.Body.String())
	}
	if f.sessionWorks(t, other.Principal.SessionID) || !f.sessionWorks(t, mine.Principal.SessionID) {
		t.Fatal("only the other session must end")
	}
	f.expectError(t, f.send(t, http.MethodDelete, "/sessions/"+other.Principal.SessionID, nil, f.signed(mine)...), http.StatusNotFound, "not_found")
}

func TestEndSessionEndsTheCurrentSessionAndClearsTheCookie(t *testing.T) {
	f := newAPIFixture(t)
	mine, _ := f.signIn(t)
	rec := f.send(t, http.MethodDelete, "/sessions/"+mine.Principal.SessionID, nil, f.signed(mine)...)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /sessions/{id} = %d: %s", rec.Code, rec.Body.String())
	}
	requireCleared(t, rec, f.a.cookie, "/")
	if f.sessionWorks(t, mine.Principal.SessionID) {
		t.Fatal("the session must end")
	}
}

func TestEndSessionOfATokenSessionClearsTheRefreshCookie(t *testing.T) {
	f := newRefreshCookieFixture(t)
	tokens, _ := f.cookieSignIn(t)
	rec := f.send(t, http.MethodDelete, "/sessions/"+tokens.SessionID, nil, bearer(tokens.AccessToken))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /sessions/{id} = %d: %s", rec.Code, rec.Body.String())
	}
	requireCleared(t, rec, f.a.refreshCookie, "/auth/token/refresh")
}

func TestEndSessionDoesNotShowWhichSessionsExist(t *testing.T) {
	f := newAPIFixture(t)
	mustRegister(t, f.a, map[string]string{"email": "omar@example.com", "username": "omar_o"}, goodPassword)
	stranger, err := f.a.Login(t.Context(), Credentials{Login: "omar@example.com", Password: goodPassword, Kind: SessionCookie})
	if err != nil {
		t.Fatal(err)
	}
	mine, _ := f.signIn(t)
	var answers []string
	for _, id := range []string{stranger.Principal.SessionID, "current", "unknown", strings.Repeat("x", 300), "00000000-0000-7000-8000-000000000000"} {
		rec := f.send(t, http.MethodDelete, "/sessions/"+id, nil, f.signed(mine)...)
		f.expectError(t, rec, http.StatusNotFound, "not_found")
		answers = append(answers, rec.Body.String())
	}
	for _, answer := range answers[1:] {
		if answer != answers[0] {
			t.Fatalf("the answers differ:\n%s\n%s", answers[0], answer)
		}
	}
	if !f.sessionWorks(t, stranger.Principal.SessionID) || !f.sessionWorks(t, mine.Principal.SessionID) {
		t.Fatal("no session may end")
	}
}

func TestEndSessionNeedsASessionAndTheCrossSiteCheck(t *testing.T) {
	f := newAPIFixture(t)
	mine, _ := f.signIn(t)
	other := f.login(t)
	path := "/sessions/" + other.Principal.SessionID
	f.expectError(t, f.send(t, http.MethodDelete, path, nil), http.StatusUnauthorized, "unauthenticated")
	f.expectError(t, f.send(t, http.MethodDelete, path, nil, f.sessionCookie(mine.Secret)), http.StatusForbidden, "csrf_failed")
	f.expectError(t, f.send(t, http.MethodDelete, path, nil, f.sessionCookie(mine.Secret), fromOrigin("https://evil.example"), header(csrfHeader, mine.CSRFToken)), http.StatusForbidden, "csrf_failed")
	if !f.sessionWorks(t, other.Principal.SessionID) {
		t.Fatal("a refused request must not end the session")
	}
}

func TestChangePasswordGivesACookieSessionANewCookie(t *testing.T) {
	f := newAPIFixture(t)
	mine, _ := f.signIn(t)
	other := f.login(t)
	f.clock.advance(time.Hour)
	request := map[string]string{"current_password": goodPassword, "new_password": newPassword}
	rec := f.send(t, http.MethodPost, "/password/change", request, f.signed(mine)...)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /password/change = %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody[cookieSessionBody](t, rec)
	cookie := cookieNamed(rec, f.a.cookie)
	if cookie == nil || cookie.Value == mine.Secret || body.SessionID == mine.Principal.SessionID || body.CSRFToken == mine.CSRFToken || body.PasswordChangeRequired {
		t.Fatalf("body = %+v, cookie = %+v", body, cookie)
	}
	if !body.ExpiresAt.Equal(inSeconds(mine.ExpiresAt)) {
		t.Fatalf("a change of the password must not extend the session: expires_at = %v, was %v", body.ExpiresAt, mine.ExpiresAt)
	}
	if cookie.MaxAge != 30*24*3600-3600 {
		t.Fatalf("Max-Age = %d", cookie.MaxAge)
	}
	if f.sessionWorks(t, mine.Principal.SessionID) || f.sessionWorks(t, other.Principal.SessionID) || !f.sessionWorks(t, body.SessionID) {
		t.Fatal("every old session must end and the new one must go on")
	}
	fresh := Login{Secret: cookie.Value, CSRFToken: body.CSRFToken, Principal: Principal{SessionID: body.SessionID}}
	if rec = f.send(t, http.MethodGet, "/sessions/current", nil, f.sessionCookie(fresh.Secret)); rec.Code != http.StatusOK {
		t.Fatalf("the new cookie does not work: %d", rec.Code)
	}
	if !f.canSignInWith(t, newPassword) || f.canSignInWith(t, goodPassword) {
		t.Fatal("the password must have changed")
	}
}

func TestChangePasswordGivesATokenSessionNewTokens(t *testing.T) {
	f := newAPIFixture(t)
	tokens, _ := f.signInWithTokens(t)
	request := map[string]string{"current_password": goodPassword, "new_password": newPassword}
	rec := f.send(t, http.MethodPost, "/password/change", request, bearer(tokens.AccessToken))
	if rec.Code != http.StatusOK || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("POST /password/change = %d, Set-Cookie = %v: %s", rec.Code, rec.Header()["Set-Cookie"], rec.Body.String())
	}
	fresh := decodeBody[tokenSessionBody](t, rec)
	if fresh.AccessToken == "" || fresh.AccessToken == tokens.AccessToken || fresh.RefreshToken == "" || fresh.SessionID == tokens.SessionID || fresh.PasswordChangeRequired {
		t.Fatalf("body = %+v", fresh)
	}
	f.expectError(t, f.send(t, http.MethodGet, "/sessions", nil, bearer(tokens.AccessToken)), http.StatusUnauthorized, "unauthenticated")
	f.expectError(t, f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": tokens.RefreshToken}), http.StatusUnauthorized, "unauthenticated")
	if listed := f.send(t, http.MethodGet, "/sessions", nil, bearer(fresh.AccessToken)); listed.Code != http.StatusOK {
		t.Fatalf("the new access token does not work: %d", listed.Code)
	}
}

func TestChangePasswordOfATokenSessionKeepsTheRefreshTokenInTheCookie(t *testing.T) {
	f := newRefreshCookieFixture(t)
	tokens, cookie := f.cookieSignIn(t)
	request := map[string]string{"current_password": goodPassword, "new_password": newPassword}
	rec := f.send(t, http.MethodPost, "/password/change", request, bearer(tokens.AccessToken))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /password/change = %d: %s", rec.Code, rec.Body.String())
	}
	renewed := cookieNamed(rec, f.a.refreshCookie)
	if renewed == nil || renewed.Value == cookie.Value || renewed.Path != "/auth/token/refresh" || decodeBody[tokenSessionBody](t, rec).RefreshToken != "" {
		t.Fatalf("cookie = %+v, body = %s", renewed, rec.Body.String())
	}
}

func TestAUserWhoMustChangeThePasswordCanChangeIt(t *testing.T) {
	f := newAPIFixture(t)
	f.restrict(t)
	login, _ := f.signIn(t)
	request := map[string]string{"current_password": goodPassword, "new_password": newPassword}
	rec := f.send(t, http.MethodPost, "/password/change", request, f.signed(login)...)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /password/change = %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody[cookieSessionBody](t, rec)
	if body.PasswordChangeRequired {
		t.Fatalf("body = %+v", body)
	}
	fresh := f.sessionCookie(cookieNamed(rec, f.a.cookie).Value)
	if listed := f.send(t, http.MethodGet, "/sessions", nil, fresh); listed.Code != http.StatusOK {
		t.Fatalf("the new session is still closed: %d %s", listed.Code, listed.Body.String())
	}
}

func TestChangePasswordTurnsDownAWrongCurrentPassword(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	request := map[string]string{"current_password": "not the password at all", "new_password": newPassword}
	f.expectError(t, f.send(t, http.MethodPost, "/password/change", request, f.signed(login)...), http.StatusUnauthorized, "invalid_credentials")
	if !f.sessionWorks(t, login.Principal.SessionID) || !f.canSignInWith(t, goodPassword) {
		t.Fatal("nothing may change")
	}
}

func TestChangePasswordReportsTheBrokenRulesOfThePolicy(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	tests := map[string][]string{
		"short":            {"min_length"},
		"password1234":     {"common_password"},
		"nina@example.com": {"login_identifier"},
	}
	for next, rules := range tests {
		rec := f.send(t, http.MethodPost, "/password/change", map[string]string{"current_password": goodPassword, "new_password": next}, f.signed(login)...)
		f.expectError(t, rec, http.StatusUnprocessableEntity, "policy_violation")
		got := decodeBody[errorBody](t, rec).Error.Rules
		for _, rule := range rules {
			if !containsRule(got, rule) {
				t.Errorf("the rules of %q = %v, want %s among them", next, got, rule)
			}
		}
	}
	if !f.sessionWorks(t, login.Principal.SessionID) || !f.canSignInWith(t, goodPassword) {
		t.Fatal("nothing may change")
	}
}

func TestChangePasswordReadsOnlyAWellFormedRequest(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	tests := []struct {
		name string
		body any
		opts []requestOption
		want int
		code string
	}{
		{"no body", nil, nil, http.StatusBadRequest, "invalid_request"},
		{"no new password", `{"current_password":"x"}`, nil, http.StatusBadRequest, "invalid_request"},
		{"no current password", `{"new_password":"x"}`, nil, http.StatusBadRequest, "invalid_request"},
		{"an unknown field", `{"current_password":"x","new_password":"y","password":"z"}`, nil, http.StatusBadRequest, "invalid_request"},
		{"a form", `current_password=x`, []requestOption{header("Content-Type", "application/x-www-form-urlencoded")}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := append(f.signed(login), tc.opts...)
			f.expectError(t, f.send(t, http.MethodPost, "/password/change", tc.body, opts...), tc.want, tc.code)
		})
	}
}

func TestChangePasswordNeedsASessionAndTheCrossSiteCheck(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	request := map[string]string{"current_password": goodPassword, "new_password": newPassword}
	f.expectError(t, f.send(t, http.MethodPost, "/password/change", request), http.StatusUnauthorized, "unauthenticated")
	f.expectError(t, f.send(t, http.MethodPost, "/password/change", request, f.sessionCookie(login.Secret), sameOrigin()), http.StatusForbidden, "csrf_failed")
	f.expectError(t, f.send(t, http.MethodPost, "/password/change", request, bearer("damaged")), http.StatusUnauthorized, "unauthenticated")
	if !f.canSignInWith(t, goodPassword) {
		t.Fatal("the password must not change")
	}
}

func TestChangePasswordIsLimitedLikeASignIn(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	wrong := map[string]string{"current_password": "not the password at all", "new_password": newPassword}
	for range 20 {
		f.send(t, http.MethodPost, "/password/change", wrong, f.signed(login)...)
	}
	right := map[string]string{"current_password": goodPassword, "new_password": newPassword}
	rec := f.send(t, http.MethodPost, "/password/change", right, f.signed(login)...)
	f.expectError(t, rec, http.StatusTooManyRequests, "rate_limited")
	if rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
}

func TestTheRouterPutsTheIDOfASessionInTheRequest(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	other := f.login(t)
	rec := f.send(t, http.MethodDelete, "/sessions/"+other.Principal.SessionID, nil, f.signed(login)...)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /sessions/{id} = %d: %s", rec.Code, rec.Body.String())
	}
	if f.sessionWorks(t, other.Principal.SessionID) || !f.sessionWorks(t, login.Principal.SessionID) {
		t.Fatalf("the session %s must have ended and the session %s must go on", other.Principal.SessionID, login.Principal.SessionID)
	}
}

func TestAFailureOfTheStoreIsLoggedAndNeverToldToTheClient(t *testing.T) {
	change := map[string]string{"current_password": goodPassword, "new_password": newPassword}
	tests := []struct {
		name, method, path string
		body               any
		sabotage           func(f *apiFixture)
	}{
		{"list", http.MethodGet, "/sessions", nil, func(f *apiFixture) {
			f.breakSessions(func(s *sessionsFault) { s.listErr = errors.New(secretReason) })
		}},
		{"current", http.MethodGet, "/sessions/current", nil, func(f *apiFixture) {
			f.breakSessions(func(s *sessionsFault) { s.listErr = errors.New(secretReason) })
		}},
		{"end", http.MethodDelete, "/sessions/00000000-0000-7000-8000-00000000dead", nil, func(f *apiFixture) {
			f.breakSessions(func(s *sessionsFault) { s.revokeErr = errors.New(secretReason) })
		}},
		{"logout all", http.MethodPost, "/logout/all", nil, func(f *apiFixture) {
			f.breakSessions(func(s *sessionsFault) { s.revokeAllErr = errors.New(secretReason) })
		}},
		{"password change", http.MethodPost, "/password/change", change, func(f *apiFixture) {
			f.a.store = &faultyStore{Store: f.a.store, txErr: errors.New(secretReason)}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, logs := capturingLogger()
			f := newAPIFixture(t, WithLogger(logger))
			login, _ := f.signIn(t)
			tc.sabotage(f)
			rec := f.send(t, tc.method, tc.path, tc.body, f.signed(login)...)
			f.expectError(t, rec, http.StatusInternalServerError, "internal_error")
			if strings.Contains(rec.Body.String(), "fire") || !strings.Contains(logs.String(), secretReason) {
				t.Fatalf("body = %s\nlog = %s", rec.Body.String(), logs.String())
			}
			if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
				t.Fatalf("a failure changes the cookies: %v", got)
			}
		})
	}
}

func TestTheCurrentSessionThatIsGoneByTheTimeItIsListedIsNotAnswered(t *testing.T) {
	f := newAPIFixture(t)
	login, _ := f.signIn(t)
	f.breakSessions(func(s *sessionsFault) { s.listEmpty = true })
	rec := f.send(t, http.MethodGet, "/sessions/current", nil, f.sessionCookie(login.Secret))
	f.expectError(t, rec, http.StatusUnauthorized, "unauthenticated")
}
