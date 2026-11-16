package limb

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func TestLoginOpensACookieSessionAndSetsItsCookie(t *testing.T) {
	f := newAPIFixture(t)
	rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin())
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Content-Type = %q, Cache-Control = %q", ct, rec.Header().Get("Cache-Control"))
	}
	body := decodeBody[cookieSessionBody](t, rec)
	cookie := cookieNamed(rec, "__Host-limb_session")
	if cookie == nil {
		t.Fatalf("no session cookie in %v", rec.Result().Cookies())
	}
	if body.UserID != string(f.user.ID) || body.SessionID == "" || body.PasswordChangeRequired {
		t.Fatalf("body = %+v", body)
	}
	if want := f.clock.now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second); !body.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", body.ExpiresAt, want)
	}
	if !f.a.keys.CheckCSRF(body.SessionID, body.CSRFToken) {
		t.Fatal("csrf_token is not the CSRF token of the session")
	}
	if cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" {
		t.Fatalf("cookie = %+v", cookie)
	}
	if cookie.MaxAge != 30*24*3600 || !cookie.Expires.Equal(body.ExpiresAt) {
		t.Fatalf("cookie lifetime: Max-Age = %d, Expires = %v", cookie.MaxAge, cookie.Expires)
	}
	if strings.Contains(rec.Body.String(), cookie.Value) {
		t.Fatal("the secret of the cookie is in the body")
	}
	resolved := f.session(t, body.SessionID)
	if resolved.Session.Kind != store.SessionCookie || resolved.Session.UserAgent != testAgent || resolved.Session.IP != "192.0.2.1" {
		t.Fatalf("session = %+v", resolved.Session)
	}
	if principal, err := f.a.Authenticate(f.request(t, http.MethodGet, Login{Secret: cookie.Value}, nil)); err != nil || principal.SessionID != body.SessionID {
		t.Fatalf("the cookie does not authenticate: %+v, %v", principal, err)
	}
}

func TestTheSessionCookieFollowsTheConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		opts     []Option
		cookie   string
		secure   bool
		sameSite http.SameSite
	}{
		{"strict", []Option{WithCookieSameSite(http.SameSiteStrictMode)}, "__Host-limb_session", true, http.SameSiteStrictMode},
		{"none", []Option{WithCookieSameSite(http.SameSiteNoneMode)}, "__Host-limb_session", true, http.SameSiteNoneMode},
		{"development", []Option{WithDevelopmentMode()}, "limb_session", false, http.SameSiteLaxMode},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAPIFixture(t, tc.opts...)
			_, rec := f.signIn(t)
			cookie := cookieNamed(rec, tc.cookie)
			if cookie == nil {
				t.Fatalf("no cookie %s in %v", tc.cookie, rec.Result().Cookies())
			}
			if cookie.Secure != tc.secure || cookie.SameSite != tc.sameSite || !cookie.HttpOnly || cookie.Path != "/" {
				t.Fatalf("cookie = %+v", cookie)
			}
		})
	}
}

func TestLoginTurnsDownWrongCredentialsAlike(t *testing.T) {
	f := newAPIFixture(t)
	wrongPassword := f.send(t, http.MethodPost, "/login", map[string]string{"login": "nina@example.com", "password": "not the password at all"}, sameOrigin())
	unknownLogin := f.send(t, http.MethodPost, "/login", map[string]string{"login": "nobody@example.com", "password": goodPassword}, sameOrigin())
	f.expectError(t, wrongPassword, http.StatusUnauthorized, "invalid_credentials")
	f.expectError(t, unknownLogin, http.StatusUnauthorized, "invalid_credentials")
	if wrongPassword.Body.String() != unknownLogin.Body.String() {
		t.Fatalf("the answers differ:\n%s\n%s", wrongPassword.Body.String(), unknownLogin.Body.String())
	}
	for _, rec := range []*httptest.ResponseRecorder{wrongPassword, unknownLogin} {
		if got := rec.Header().Get("Set-Cookie"); got != "" {
			t.Fatalf("a failed sign-in sets a cookie: %s", got)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
	}
}

func TestLoginTellsABlockedAccountAfterTheRightPassword(t *testing.T) {
	f := newAPIFixture(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	f.expectError(t, f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin()), http.StatusForbidden, "user_blocked")
	wrong := map[string]string{"login": "nina@example.com", "password": "not the password at all"}
	f.expectError(t, f.send(t, http.MethodPost, "/login", wrong, sameOrigin()), http.StatusUnauthorized, "invalid_credentials")
}

func TestLoginOfAUserWhoMustChangeThePasswordSaysSo(t *testing.T) {
	f := newAPIFixture(t)
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin())
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login = %d: %s", rec.Code, rec.Body.String())
	}
	if body := decodeBody[cookieSessionBody](t, rec); !body.PasswordChangeRequired {
		t.Fatalf("body = %+v", body)
	}
}

func TestLoginSlowsDownAfterTooManyFailures(t *testing.T) {
	f := newAPIFixture(t)
	wrong := map[string]string{"login": "nina@example.com", "password": "not the password at all"}
	for i := range 5 {
		if rec := f.send(t, http.MethodPost, "/login", wrong, sameOrigin()); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d", i+1, rec.Code)
		}
	}
	rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin())
	f.expectError(t, rec, http.StatusTooManyRequests, "rate_limited")
	seconds, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || seconds < 1 || seconds > 15*60 {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("a limited sign-in sets a cookie")
	}
	f.clock.advance(time.Duration(seconds) * time.Second)
	if rec = f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin()); rec.Code != http.StatusOK {
		t.Fatalf("after the pause POST /login = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginCountsTheAddressThatTrustedProxiesReport(t *testing.T) {
	f := newAPIFixture(t, WithTrustedProxies(netip.MustParsePrefix("192.0.2.0/24")))
	rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin(), header("X-Forwarded-For", "198.51.100.23, 192.0.2.77"), fromAddress("192.0.2.1:4000"))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login = %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody[cookieSessionBody](t, rec)
	if got := f.session(t, body.SessionID).Session.IP; got != "198.51.100.23" {
		t.Fatalf("the session was opened from %q", got)
	}
	other := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin(), header("X-Forwarded-For", "198.51.100.99"), fromAddress("203.0.113.9:4000"))
	if got := f.session(t, decodeBody[cookieSessionBody](t, other).SessionID).Session.IP; got != "203.0.113.9" {
		t.Fatalf("a header from a peer that is no proxy must be ignored, got %q", got)
	}
}

func TestLoginChecksWhereTheRequestComesFrom(t *testing.T) {
	tests := []struct {
		name string
		opts []requestOption
		want int
	}{
		{"same origin", []requestOption{sameOrigin()}, http.StatusOK},
		{"the origin of the site", []requestOption{fromOrigin(appOrigin)}, http.StatusOK},
		{"the origin of the site and the same site", []requestOption{fromOrigin(appOrigin), header("Sec-Fetch-Site", "same-site")}, http.StatusOK},
		{"another origin", []requestOption{fromOrigin("https://evil.example")}, http.StatusForbidden},
		{"another scheme", []requestOption{fromOrigin("http://app.example.com")}, http.StatusForbidden},
		{"another port", []requestOption{fromOrigin("https://app.example.com:8443")}, http.StatusForbidden},
		{"a null origin", []requestOption{fromOrigin("null")}, http.StatusForbidden},
		{"another site", []requestOption{header("Sec-Fetch-Site", "cross-site"), fromOrigin("https://evil.example")}, http.StatusForbidden},
		{"typed in the address bar", []requestOption{header("Sec-Fetch-Site", "none")}, http.StatusForbidden},
		{"no hint at all", nil, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAPIFixture(t)
			rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), tc.opts...)
			if rec.Code != tc.want {
				t.Fatalf("POST /login = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want != http.StatusOK {
				f.expectError(t, rec, http.StatusForbidden, "csrf_failed")
				if rec.Header().Get("Set-Cookie") != "" {
					t.Fatal("a refused sign-in sets a cookie")
				}
			}
		})
	}
}

func TestLoginAcceptsAnOriginThatTheApplicationTrusts(t *testing.T) {
	f := newAPIFixture(t, WithTrustedOrigins("https://spa.example.net"))
	if rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), fromOrigin("https://spa.example.net")); rec.Code != http.StatusOK {
		t.Fatalf("POST /login from a trusted origin = %d: %s", rec.Code, rec.Body.String())
	}
	f.expectError(t, f.send(t, http.MethodPost, "/login", f.loginRequest(), fromOrigin("https://spa.example.org")), http.StatusForbidden, "csrf_failed")
}

func TestLoginOnlyChecksTheOriginAndNeedsNoCSRFToken(t *testing.T) {
	f := newAPIFixture(t)
	rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin(), header(csrfHeader, "not a token"))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestLoginTrustsTheSchemeFromAProxyOnlyIfItIsOne(t *testing.T) {
	plain := func(f *apiFixture, opts ...requestOption) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://app.example.com/login", bodyOf(t, f.loginRequest()))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", appOrigin)
		for _, opt := range opts {
			opt(r)
		}
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, r)
		return rec
	}
	untrusting := newAPIFixture(t)
	if rec := plain(untrusting, header("X-Forwarded-Proto", "https")); rec.Code != http.StatusForbidden {
		t.Fatalf("a forwarded scheme without a proxy = %d", rec.Code)
	}
	trusting := newAPIFixture(t, WithTrustedProxies(netip.MustParsePrefix("192.0.2.0/24")))
	if rec := plain(trusting, header("X-Forwarded-Proto", "https")); rec.Code != http.StatusOK {
		t.Fatalf("a forwarded scheme from a proxy = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := plain(trusting, header("X-Forwarded-Proto", "http")); rec.Code != http.StatusForbidden {
		t.Fatalf("a forwarded plain scheme = %d", rec.Code)
	}
}

func TestLoginReadsOnlyAWellFormedJSONBody(t *testing.T) {
	good := `{"login":"nina@example.com","password":"` + goodPassword + `"}`
	huge := `{"login":"nina@example.com","password":"` + strings.Repeat("a", 65<<10) + `"}`
	tests := []struct {
		name string
		body any
		opts []requestOption
		want int
		code string
	}{
		{"no body", nil, nil, http.StatusBadRequest, "invalid_request"},
		{"blank body", "  \n", []requestOption{asJSON()}, http.StatusBadRequest, "invalid_request"},
		{"not JSON", "login=nina", []requestOption{asJSON()}, http.StatusBadRequest, "invalid_request"},
		{"an array", `["nina@example.com"]`, nil, http.StatusBadRequest, "invalid_request"},
		{"null", `null`, nil, http.StatusBadRequest, "invalid_request"},
		{"an unknown field", `{"login":"nina@example.com","password":"x","remember":true}`, nil, http.StatusBadRequest, "invalid_request"},
		{"a number for the password", `{"login":"nina@example.com","password":1}`, nil, http.StatusBadRequest, "invalid_request"},
		{"no password", `{"login":"nina@example.com"}`, nil, http.StatusBadRequest, "invalid_request"},
		{"no login", `{"password":"x"}`, nil, http.StatusBadRequest, "invalid_request"},
		{"an empty password", `{"login":"nina@example.com","password":""}`, nil, http.StatusBadRequest, "invalid_request"},
		{"two values", good + good, nil, http.StatusBadRequest, "invalid_request"},
		{"trailing text", good + " x", nil, http.StatusBadRequest, "invalid_request"},
		{"a form", good, []requestOption{header("Content-Type", "application/x-www-form-urlencoded")}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"plain text", good, []requestOption{header("Content-Type", "text/plain")}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"no content type", good, []requestOption{header("Content-Type", "")}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"a body that is too large", huge, nil, http.StatusRequestEntityTooLarge, "invalid_request"},
		{"JSON with a charset", good, []requestOption{header("Content-Type", "application/json; charset=utf-8")}, http.StatusOK, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newAPIFixture(t)
			opts := append([]requestOption{sameOrigin()}, tc.opts...)
			rec := f.send(t, http.MethodPost, "/login", tc.body, opts...)
			if tc.want == http.StatusOK {
				if rec.Code != http.StatusOK {
					t.Fatalf("POST /login = %d: %s", rec.Code, rec.Body.String())
				}
				return
			}
			f.expectError(t, rec, tc.want, tc.code)
			if rec.Header().Get("Set-Cookie") != "" {
				t.Fatal("a refused request sets a cookie")
			}
		})
	}
}

func TestSigningInAgainEndsTheSessionTheRequestCameWith(t *testing.T) {
	f := newAPIFixture(t)
	first, _ := f.signIn(t)
	rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin(), f.sessionCookie(first.Secret))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login = %d: %s", rec.Code, rec.Body.String())
	}
	second := decodeBody[cookieSessionBody](t, rec)
	if second.SessionID == first.Principal.SessionID || f.sessionWorks(t, first.Principal.SessionID) || !f.sessionWorks(t, second.SessionID) {
		t.Fatalf("the first session must end and the second go on: %+v", second)
	}
}

func TestSigningInAsAnotherUserEndsTheSessionOfTheFirst(t *testing.T) {
	f := newAPIFixture(t)
	mustRegister(t, f.a, map[string]string{"email": "omar@example.com", "username": "omar_o"}, goodPassword)
	first, _ := f.signIn(t)
	request := map[string]string{"login": "omar@example.com", "password": goodPassword}
	rec := f.send(t, http.MethodPost, "/login", request, sameOrigin(), f.sessionCookie(first.Secret))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login = %d: %s", rec.Code, rec.Body.String())
	}
	if f.sessionWorks(t, first.Principal.SessionID) {
		t.Fatal("the session of the first user must end")
	}
}

func TestSigningInWithACookieThatMeansNothingJustSignsIn(t *testing.T) {
	f := newAPIFixture(t)
	for _, value := range []string{"", "x", strings.Repeat("A", 43), "not a secret\n"} {
		rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin(), f.sessionCookie(value))
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /login with the cookie %q = %d: %s", value, rec.Code, rec.Body.String())
		}
	}
}

func TestSigningInOverACookieThatMeansNothingLogsNothing(t *testing.T) {
	logger, logs := capturingLogger()
	f := newAPIFixture(t, WithLogger(logger))
	for _, value := range []string{strings.Repeat("A", 43), "not a secret"} {
		f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin(), f.sessionCookie(value))
	}
	if strings.Contains(logs.String(), "level=WARN") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("the log has complaints:\n%s", logs.String())
	}
}

func TestSigningInGoesOnWhenTheOldSessionCannotBeEnded(t *testing.T) {
	logger, logs := capturingLogger()
	f := newAPIFixture(t, WithLogger(logger))
	first, _ := f.signIn(t)
	f.breakSessions(func(s *sessionsFault) { s.revokeErr = errors.New(secretReason) })
	rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin(), f.sessionCookie(first.Secret))
	if rec.Code != http.StatusOK || cookieNamed(rec, f.a.cookie) == nil {
		t.Fatalf("POST /login = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), secretReason) {
		t.Fatalf("the failure to end the old session is not logged:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), first.Secret) {
		t.Fatal("the secret of the session is in the log")
	}
}

func TestAFailedSignInLeavesThePresentedSessionAlone(t *testing.T) {
	f := newAPIFixture(t)
	first, _ := f.signIn(t)
	wrong := map[string]string{"login": "nina@example.com", "password": "not the password at all"}
	f.expectError(t, f.send(t, http.MethodPost, "/login", wrong, sameOrigin(), f.sessionCookie(first.Secret)), http.StatusUnauthorized, "invalid_credentials")
	if !f.sessionWorks(t, first.Principal.SessionID) {
		t.Fatal("a failed sign-in must not end the session")
	}
}

func TestTheTokenRouteSignsInWithTokens(t *testing.T) {
	f := newAPIFixture(t)
	body, rec := f.signInWithTokens(t)
	if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if body.UserID != string(f.user.ID) || body.TokenType != "Bearer" || body.AccessToken == "" || body.RefreshToken == "" || body.PasswordChangeRequired {
		t.Fatalf("body = %+v", body)
	}
	if want := f.clock.now().Add(10 * time.Minute).UTC().Truncate(time.Second); !body.AccessExpiresAt.Equal(want) {
		t.Fatalf("access_expires_at = %v, want %v", body.AccessExpiresAt, want)
	}
	if want := f.clock.now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second); !body.RefreshExpiresAt.Equal(want) {
		t.Fatalf("refresh_expires_at = %v, want %v", body.RefreshExpiresAt, want)
	}
	if want := f.clock.now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second); !body.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", body.ExpiresAt, want)
	}
	if resolved := f.session(t, body.SessionID); resolved.Session.Kind != store.SessionToken || resolved.Session.UserAgent != testAgent {
		t.Fatalf("session = %+v", resolved.Session)
	}
	if err := f.bearerError(t, body.AccessToken); err != nil {
		t.Fatalf("the access token does not work: %v", err)
	}
}

func TestTheTokenRouteNeedsNoOriginAndTurnsDownBadCredentials(t *testing.T) {
	f := newAPIFixture(t)
	wrong := map[string]string{"login": "nina@example.com", "password": "not the password at all"}
	f.expectError(t, f.send(t, http.MethodPost, "/token", wrong), http.StatusUnauthorized, "invalid_credentials")
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	f.expectError(t, f.send(t, http.MethodPost, "/token", f.loginRequest()), http.StatusForbidden, "user_blocked")
	f.expectError(t, f.send(t, http.MethodPost, "/token", "[]"), http.StatusBadRequest, "invalid_request")
}

func TestTheTokenRouteOfAUserWhoMustChangeThePasswordSaysSo(t *testing.T) {
	f := newAPIFixture(t)
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	body, _ := f.signInWithTokens(t)
	if !body.PasswordChangeRequired {
		t.Fatalf("body = %+v", body)
	}
	if err := f.bearerError(t, body.AccessToken); !errors.Is(err, ErrPasswordChangeRequired) {
		t.Fatalf("the access token of a user who must change the password = %v", err)
	}
}

func TestRefreshExchangesTheRefreshTokenInTheBody(t *testing.T) {
	f := newAPIFixture(t)
	first, _ := f.signInWithTokens(t)
	f.clock.advance(time.Minute)
	rec := f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": first.RefreshToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token/refresh = %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("a refresh without the cookie mode sets a cookie")
	}
	fields := decodeMap(t, rec)
	for _, name := range []string{"user_id", "session_id", "expires_at", "password_change_required"} {
		if _, found := fields[name]; found {
			t.Fatalf("the answer of a refresh has %q", name)
		}
	}
	second := decodeBody[tokensBody](t, rec)
	if second.TokenType != "Bearer" || second.AccessToken == "" || second.AccessToken == first.AccessToken || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Fatalf("tokens = %+v", second)
	}
	if err := f.bearerError(t, second.AccessToken); err != nil {
		t.Fatalf("the new access token does not work: %v", err)
	}
	again := f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": first.RefreshToken})
	f.expectError(t, again, http.StatusUnauthorized, "unauthenticated")
	if again.Header().Get("WWW-Authenticate") != "" || again.Header().Get("Set-Cookie") != "" {
		t.Fatalf("headers = %v", again.Header())
	}
}

func TestRefreshEndsTheSessionWhenAnOldTokenIsUsedAgainLater(t *testing.T) {
	f := newAPIFixture(t)
	first, _ := f.signInWithTokens(t)
	second := decodeBody[tokensBody](t, f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": first.RefreshToken}))
	f.clock.advance(5 * time.Second)
	f.expectError(t, f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": first.RefreshToken}), http.StatusUnauthorized, "unauthenticated")
	if !f.sessionWorks(t, first.SessionID) {
		t.Fatal("a second request within ten seconds must not end the session")
	}
	f.clock.advance(time.Minute)
	f.expectError(t, f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": first.RefreshToken}), http.StatusUnauthorized, "unauthenticated")
	if f.sessionWorks(t, first.SessionID) {
		t.Fatal("the session must end when an old token is used again later")
	}
	f.expectError(t, f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": second.RefreshToken}), http.StatusUnauthorized, "unauthenticated")
}

func TestRefreshReadsOnlyAWellFormedRequest(t *testing.T) {
	f := newAPIFixture(t)
	tests := []struct {
		name string
		body any
		opts []requestOption
		want int
		code string
	}{
		{"no body", nil, nil, http.StatusBadRequest, "invalid_request"},
		{"an empty token", `{"refresh_token":""}`, nil, http.StatusBadRequest, "invalid_request"},
		{"a field that is not known", `{"refresh_token":"x","access_token":"y"}`, nil, http.StatusBadRequest, "invalid_request"},
		{"a token that is not one", `{"refresh_token":"x"}`, nil, http.StatusUnauthorized, "unauthenticated"},
		{"a form", `refresh_token=x`, []requestOption{header("Content-Type", "application/x-www-form-urlencoded")}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f.expectError(t, f.send(t, http.MethodPost, "/token/refresh", tc.body, tc.opts...), tc.want, tc.code)
		})
	}
}

func TestRefreshOfAUserWhoMustChangeThePasswordGivesARestrictedToken(t *testing.T) {
	f := newAPIFixture(t)
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	first, _ := f.signInWithTokens(t)
	rec := f.send(t, http.MethodPost, "/token/refresh", map[string]string{"refresh_token": first.RefreshToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token/refresh = %d: %s", rec.Code, rec.Body.String())
	}
	second := decodeBody[tokensBody](t, rec)
	if err := f.bearerError(t, second.AccessToken); !errors.Is(err, ErrPasswordChangeRequired) {
		t.Fatalf("the new access token of a user who must change the password = %v", err)
	}
}
