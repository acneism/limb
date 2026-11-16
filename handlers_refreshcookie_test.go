package limb

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newRefreshCookieFixture(t *testing.T, opts ...Option) *apiFixture {
	t.Helper()
	all := append([]Option{WithMountPath("/auth"), WithRefreshCookie()}, opts...)
	return newAPIFixture(t, all...)
}

func (f *apiFixture) refreshCookie(value string) requestOption {
	return withCookie(f.a.refreshCookie, value)
}

func (f *apiFixture) cookieSignIn(t *testing.T) (tokenSessionBody, *http.Cookie) {
	t.Helper()
	rec := f.send(t, http.MethodPost, "/token", f.loginRequest(), fromOrigin(appOrigin))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token = %d: %s", rec.Code, rec.Body.String())
	}
	cookie := cookieNamed(rec, f.a.refreshCookie)
	if cookie == nil {
		t.Fatal("POST /token set no refresh cookie")
	}
	return decodeBody[tokenSessionBody](t, rec), cookie
}

func TestTheRefreshTokenCanLiveInACookie(t *testing.T) {
	f := newRefreshCookieFixture(t)
	body, cookie := f.cookieSignIn(t)
	if body.RefreshToken != "" || body.AccessToken == "" || body.RefreshExpiresAt.IsZero() {
		t.Fatalf("body = %+v", body)
	}
	if _, found := decodeMap(t, f.send(t, http.MethodPost, "/token", f.loginRequest(), sameOrigin()))["refresh_token"]; found {
		t.Fatal("the refresh token is in the body")
	}
	if cookie.Name != "__Secure-limb_refresh" || cookie.Path != "/auth/token/refresh" || !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" || cookie.Value == "" {
		t.Fatalf("cookie = %+v", cookie)
	}
	if cookie.MaxAge != 7*24*3600 || !cookie.Expires.Equal(body.RefreshExpiresAt) {
		t.Fatalf("lifetime: Max-Age = %d, Expires = %v, refresh_expires_at = %v", cookie.MaxAge, cookie.Expires, body.RefreshExpiresAt)
	}
	f.clock.advance(time.Minute)
	rec := f.send(t, http.MethodPost, "/token/refresh", nil, fromOrigin(appOrigin), f.refreshCookie(cookie.Value))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token/refresh = %d: %s", rec.Code, rec.Body.String())
	}
	next := decodeBody[tokensBody](t, rec)
	renewed := cookieNamed(rec, f.a.refreshCookie)
	if next.RefreshToken != "" || next.AccessToken == "" || next.AccessToken == body.AccessToken || renewed == nil || renewed.Value == cookie.Value || renewed.Path != cookie.Path {
		t.Fatalf("tokens = %+v, cookie = %+v", next, renewed)
	}
	if strings.Contains(rec.Body.String(), renewed.Value) {
		t.Fatal("the refresh token is in the body")
	}
	if err := f.bearerError(t, next.AccessToken); err != nil {
		t.Fatalf("the new access token does not work: %v", err)
	}
}

func TestTheRefreshCookieIsScopedToTheMountPath(t *testing.T) {
	tests := map[string]string{
		"/":          "/token/refresh",
		"/auth":      "/auth/token/refresh",
		"/api/v1":    "/api/v1/token/refresh",
		"/a.b_c~d-e": "/a.b_c~d-e/token/refresh",
	}
	for mount, want := range tests {
		f := newAPIFixture(t, WithMountPath(mount), WithRefreshCookie())
		_, cookie := f.cookieSignIn(t)
		if cookie.Path != want {
			t.Errorf("mount path %q: cookie path = %q, want %q", mount, cookie.Path, want)
		}
	}
}

func TestTheRefreshCookieInDevelopmentModeHasNoPrefixAndIsNotSecure(t *testing.T) {
	f := newRefreshCookieFixture(t, WithDevelopmentMode())
	_, cookie := f.cookieSignIn(t)
	if cookie.Name != "limb_refresh" || cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie = %+v", cookie)
	}
}

func TestTheRefreshCookieRoutesCheckTheOrigin(t *testing.T) {
	f := newRefreshCookieFixture(t)
	f.expectError(t, f.send(t, http.MethodPost, "/token", f.loginRequest()), http.StatusForbidden, "csrf_failed")
	f.expectError(t, f.send(t, http.MethodPost, "/token", f.loginRequest(), fromOrigin("https://evil.example")), http.StatusForbidden, "csrf_failed")
	_, cookie := f.cookieSignIn(t)
	for _, opts := range [][]requestOption{
		{f.refreshCookie(cookie.Value)},
		{f.refreshCookie(cookie.Value), fromOrigin("https://evil.example")},
		{f.refreshCookie(cookie.Value), header("Sec-Fetch-Site", "cross-site")},
	} {
		rec := f.send(t, http.MethodPost, "/token/refresh", nil, opts...)
		f.expectError(t, rec, http.StatusForbidden, "csrf_failed")
		if rec.Header().Get("Set-Cookie") != "" {
			t.Fatalf("a refused refresh changes the cookie: %s", rec.Header().Get("Set-Cookie"))
		}
	}
	if rec := f.send(t, http.MethodPost, "/token/refresh", nil, sameOrigin(), f.refreshCookie(cookie.Value)); rec.Code != http.StatusOK {
		t.Fatalf("the refresh token was used up by a refused request: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRefreshWithTheCookieRefusesATokenInTheBody(t *testing.T) {
	f := newRefreshCookieFixture(t)
	_, cookie := f.cookieSignIn(t)
	rec := f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": cookie.Value}, sameOrigin())
	f.expectError(t, rec, http.StatusBadRequest, "invalid_request")
	f.expectError(t, f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": cookie.Value}, sameOrigin(), f.refreshCookie(cookie.Value)), http.StatusBadRequest, "invalid_request")
	if rec = f.send(t, http.MethodPost, "/token/refresh", "{}", sameOrigin(), f.refreshCookie(cookie.Value)); rec.Code != http.StatusOK {
		t.Fatalf("an empty object as the body = %d: %s", rec.Code, rec.Body.String())
	}
}

func requireCleared(t *testing.T, rec *httptest.ResponseRecorder, name, path string) {
	t.Helper()
	cookie := cookieNamed(rec, name)
	if cookie == nil || cookie.Value != "" || cookie.MaxAge >= 0 || cookie.Path != path || !cookie.HttpOnly || cookie.Expires.Unix() != 0 {
		t.Fatalf("the cookie %s was not cleared: %+v in %v", name, cookie, rec.Header()["Set-Cookie"])
	}
}

func TestARefreshThatFailsClearsTheCookie(t *testing.T) {
	f := newRefreshCookieFixture(t)
	body, cookie := f.cookieSignIn(t)
	path := "/auth/token/refresh"
	for name, opts := range map[string][]requestOption{
		"a token that does not exist": {sameOrigin(), f.refreshCookie(strings.Repeat("A", 43))},
		"a damaged token":             {sameOrigin(), f.refreshCookie("damaged")},
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.send(t, http.MethodPost, "/token/refresh", nil, opts...)
			f.expectError(t, rec, http.StatusUnauthorized, "unauthenticated")
			requireCleared(t, rec, f.a.refreshCookie, path)
		})
	}
	rec := f.send(t, http.MethodPost, "/token/refresh", nil, sameOrigin())
	f.expectError(t, rec, http.StatusUnauthorized, "unauthenticated")
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("a refresh without a cookie sets %v", got)
	}
	f.clock.advance(8 * 24 * time.Hour)
	rec = f.send(t, http.MethodPost, "/token/refresh", nil, sameOrigin(), f.refreshCookie(cookie.Value))
	f.expectError(t, rec, http.StatusUnauthorized, "unauthenticated")
	requireCleared(t, rec, f.a.refreshCookie, path)
	if f.sessionWorks(t, body.SessionID) && f.a.sessionActive(f.session(t, body.SessionID).Session, f.clock.now()) {
		t.Fatal("the session must be over")
	}
}

func TestARefreshThatLostARaceKeepsTheCookieOfTheWinner(t *testing.T) {
	f := newRefreshCookieFixture(t)
	_, cookie := f.cookieSignIn(t)
	winner := f.send(t, http.MethodPost, "/token/refresh", nil, sameOrigin(), f.refreshCookie(cookie.Value))
	if winner.Code != http.StatusOK || cookieNamed(winner, f.a.refreshCookie) == nil {
		t.Fatalf("the first refresh = %d: %s", winner.Code, winner.Body.String())
	}
	f.clock.advance(3 * time.Second)
	loser := f.send(t, http.MethodPost, "/token/refresh", nil, sameOrigin(), f.refreshCookie(cookie.Value))
	f.expectError(t, loser, http.StatusUnauthorized, "unauthenticated")
	if got := loser.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("the loser of a race changes the cookie: %v", got)
	}
	f.clock.advance(time.Minute)
	replay := f.send(t, http.MethodPost, "/token/refresh", nil, sameOrigin(), f.refreshCookie(cookie.Value))
	f.expectError(t, replay, http.StatusUnauthorized, "unauthenticated")
	requireCleared(t, replay, f.a.refreshCookie, "/auth/token/refresh")
}

func TestSigningOutClearsTheRefreshCookie(t *testing.T) {
	f := newRefreshCookieFixture(t)
	body, _ := f.cookieSignIn(t)
	rec := f.send(t, http.MethodPost, "/logout", nil, bearer(body.AccessToken))
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("POST /logout = %d: %s", rec.Code, rec.Body.String())
	}
	requireCleared(t, rec, f.a.refreshCookie, "/auth/token/refresh")
	if cookieNamed(rec, f.a.cookie) != nil {
		t.Fatal("signing out of a token session clears the cookie of a cookie session")
	}
	if f.sessionWorks(t, body.SessionID) {
		t.Fatal("the session must end")
	}
}

func TestSigningOutWithoutASessionClearsBothCookies(t *testing.T) {
	f := newRefreshCookieFixture(t)
	rec := f.send(t, http.MethodPost, "/logout", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST /logout = %d: %s", rec.Code, rec.Body.String())
	}
	requireCleared(t, rec, f.a.cookie, "/")
	requireCleared(t, rec, f.a.refreshCookie, "/auth/token/refresh")
}

func TestARefreshThatBreaksInsideLeavesTheCookieAlone(t *testing.T) {
	f := newRefreshCookieFixture(t)
	_, cookie := f.cookieSignIn(t)
	f.a.store = &faultyStore{Store: f.a.store, txErr: errors.New("a transaction cannot be started")}
	rec := f.send(t, http.MethodPost, "/token/refresh", nil, sameOrigin(), f.refreshCookie(cookie.Value))
	f.expectError(t, rec, http.StatusInternalServerError, "internal_error")
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("a failure of ours must not take the cookie of the user away: %v", got)
	}
}

func TestAReplayAfterTheSessionEndedStillClearsTheCookie(t *testing.T) {
	f := newRefreshCookieFixture(t)
	body, cookie := f.cookieSignIn(t)
	rec := f.send(t, http.MethodPost, "/token/refresh", nil, sameOrigin(), f.refreshCookie(cookie.Value))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token/refresh = %d: %s", rec.Code, rec.Body.String())
	}
	next := decodeBody[tokensBody](t, rec)
	if out := f.send(t, http.MethodPost, "/logout", nil, bearer(next.AccessToken)); out.Code != http.StatusNoContent {
		t.Fatalf("POST /logout = %d", out.Code)
	}
	f.clock.advance(time.Minute)
	replay := f.send(t, http.MethodPost, "/token/refresh", nil, sameOrigin(), f.refreshCookie(cookie.Value))
	f.expectError(t, replay, http.StatusUnauthorized, "unauthenticated")
	requireCleared(t, replay, f.a.refreshCookie, "/auth/token/refresh")
	if f.sessionWorks(t, body.SessionID) {
		t.Fatal("the session must stay ended")
	}
}
