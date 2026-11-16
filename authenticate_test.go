package limb

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func TestAuthenticateFindsTheSessionOfACookie(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	p, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil))
	if err != nil || p != login.Principal {
		t.Fatalf("Authenticate = %+v, %v; want %+v", p, err, login.Principal)
	}
	if p.UserID != f.user.ID || p.SessionKind != SessionCookie || p.MustChangePassword {
		t.Fatalf("Principal = %+v", p)
	}
}

func TestAuthenticateRejectsRequestsWithoutAValidCookie(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	valid := login.Secret
	cases := map[string]func(*http.Request){
		"no cookie":            func(r *http.Request) { r.Header.Del("Cookie") },
		"another cookie name":  func(r *http.Request) { r.Header.Set("Cookie", "session="+valid) },
		"empty value":          func(r *http.Request) { r.Header.Set("Cookie", f.a.cookie+"=") },
		"too short":            func(r *http.Request) { r.Header.Set("Cookie", f.a.cookie+"="+valid[:42]) },
		"too long":             func(r *http.Request) { r.Header.Set("Cookie", f.a.cookie+"="+valid+"A") },
		"huge":                 func(r *http.Request) { r.Header.Set("Cookie", f.a.cookie+"="+strings.Repeat("A", 100000)) },
		"not base64url":        func(r *http.Request) { r.Header.Set("Cookie", f.a.cookie+"="+strings.Repeat("!", 43)) },
		"unknown secret":       func(r *http.Request) { r.Header.Set("Cookie", f.a.cookie+"="+strings.Repeat("A", 43)) },
		"the CSRF token":       func(r *http.Request) { r.Header.Set("Cookie", f.a.cookie+"="+login.CSRFToken) },
		"the name of a secret": func(r *http.Request) { r.Header.Set("Cookie", f.a.cookie+"="+login.Principal.SessionID) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			r := f.request(t, http.MethodGet, login, nil)
			edit(r)
			if p, err := f.a.Authenticate(r); err != ErrUnauthenticated || p != (Principal{}) { //nolint:errorlint
				t.Fatalf("Authenticate = %+v, %v; want ErrUnauthenticated exactly and an empty principal", p, err)
			}
		})
	}
}

func TestABearerRequestNeverFallsBackToTheCookie(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	for _, header := range []string{"Bearer", "Bearer ", "Bearer x", "bearer x", "BEARER x", "  Bearer   x"} {
		r := f.request(t, http.MethodGet, login, map[string]string{"Authorization": header})
		if _, err := f.a.Authenticate(r); err != ErrUnauthenticated { //nolint:errorlint
			t.Errorf("Authorization %q with a good cookie: %v, want ErrUnauthenticated", header, err)
		}
	}
	for _, header := range []string{"Basic dXNlcjpwYXNz", "Token x", "Bearerx", ""} {
		r := f.request(t, http.MethodGet, login, map[string]string{"Authorization": header})
		if _, err := f.a.Authenticate(r); err != nil {
			t.Errorf("Authorization %q is not a bearer token and the cookie must be used: %v", header, err)
		}
	}
	r := f.request(t, http.MethodGet, login, nil)
	r.Header.Add("Authorization", "Basic dXNlcjpwYXNz")
	r.Header.Add("Authorization", "Bearer x")
	if _, err := f.a.Authenticate(r); err != ErrUnauthenticated { //nolint:errorlint
		t.Errorf("a bearer token among several headers: %v, want ErrUnauthenticated", err)
	}
}

func TestAuthenticateChecksTheStateOfTheSession(t *testing.T) {
	f := newSessionFixture(t, WithSessionTTL(time.Hour, 20*time.Minute))
	check := func(login Login) error {
		_, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil))
		return err
	}

	justBefore := f.login(t)
	f.clock.advance(20*time.Minute - time.Microsecond)
	if err := check(justBefore); err != nil {
		t.Fatalf("just before the idle limit: Authenticate = %v, want success", err)
	}

	idle := f.login(t)
	f.clock.advance(20 * time.Minute)
	if err := check(idle); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("exactly at the idle limit: Authenticate = %v, want ErrUnauthenticated", err)
	}
	f.clock.advance(time.Second)
	if err := check(idle); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("later: Authenticate = %v, an idle session does not come back", err)
	}

	busy := f.login(t)
	expires := f.session(t, busy.Principal.SessionID).Session.ExpiresAt
	for range 5 {
		f.clock.advance(10 * time.Minute)
		if err := check(busy); err != nil {
			t.Fatalf("a session that is used does not go idle: %v", err)
		}
	}
	f.clock.advance(expires.Sub(f.clock.now()) - time.Microsecond)
	if err := check(busy); err != nil {
		t.Fatalf("just before the absolute limit: Authenticate = %v, want success", err)
	}
	f.clock.advance(time.Microsecond)
	if err := check(busy); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("exactly at the absolute limit: Authenticate = %v, want ErrUnauthenticated", err)
	}

	ended := f.login(t)
	if err := f.a.store.Sessions().Revoke(t.Context(), f.a.tenant, string(f.user.ID), ended.Principal.SessionID, f.clock.now()); err != nil {
		t.Fatal(err)
	}
	if err := check(ended); err != ErrUnauthenticated { //nolint:errorlint
		t.Fatalf("a session that was ended: Authenticate = %v, want ErrUnauthenticated", err)
	}
}

func TestAuthenticateChecksTheStateOfTheUser(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	cases := []struct {
		name string
		edit func(*store.User)
		want error
	}{
		{"active", func(*store.User) {}, nil},
		{"blocked for good", func(u *store.User) { u.Status = store.StatusBlocked }, ErrUnauthenticated},
		{"blocked for an hour", func(u *store.User) {
			u.Status, u.BlockedUntil = store.StatusBlocked, f.clock.now().Add(time.Hour)
		}, ErrUnauthenticated},
		{"the block ended", func(u *store.User) {
			u.Status, u.BlockedUntil = store.StatusBlocked, f.clock.now().Add(-time.Second)
		}, nil},
		{"the block ends now", func(u *store.User) { u.Status, u.BlockedUntil = store.StatusBlocked, f.clock.now() }, nil},
		{"deleted", func(u *store.User) { u.Status = store.StatusDeleted }, ErrUnauthenticated},
	}
	for _, tc := range cases {
		f.change(t, tc.edit)
		_, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil))
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s: Authenticate = %v, want %v", tc.name, err, tc.want)
		}
		f.change(t, func(u *store.User) { u.Status, u.BlockedUntil = store.StatusActive, time.Time{} })
	}
}

func TestAuthenticateMarksTheSessionAsUsedAtMostOnceAMinute(t *testing.T) {
	f := newSessionFixture(t)
	var touched []string
	login := f.login(t)
	f.breakSessions(func(s *sessionsFault) { s.touched = &touched })
	start := f.session(t, login.Principal.SessionID).Session.LastSeenAt
	f.clock.advance(touchInterval - time.Microsecond)
	for range 3 {
		if _, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil)); err != nil {
			t.Fatal(err)
		}
	}
	if len(touched) != 0 {
		t.Fatalf("a session used within a minute must not be written: %v", touched)
	}
	f.clock.advance(time.Microsecond)
	if _, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil)); err != nil {
		t.Fatal(err)
	}
	if len(touched) != 1 || touched[0] != login.Principal.SessionID {
		t.Fatalf("touched = %v, want the session once after a minute", touched)
	}
	if got := f.session(t, login.Principal.SessionID).Session.LastSeenAt; !got.Equal(start.Add(touchInterval)) {
		t.Fatalf("LastSeenAt = %v, want %v", got, start.Add(touchInterval))
	}
	for range 3 {
		if _, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil)); err != nil {
			t.Fatal(err)
		}
	}
	if len(touched) != 1 {
		t.Fatalf("the session was written again within a minute: %v", touched)
	}
}

func TestAFailedTouchDoesNotFailTheRequest(t *testing.T) {
	logger, logs := capturingLogger()
	f := newSessionFixture(t, WithLogger(logger))
	login := f.login(t)
	f.breakSessions(func(s *sessionsFault) { s.touchErr = errors.New("database is down") })
	f.clock.advance(time.Hour)
	if _, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil)); err != nil {
		t.Fatalf("Authenticate = %v, want success", err)
	}
	if !strings.Contains(logs.String(), "cannot be saved") {
		t.Fatalf("the problem must be logged:\n%s", logs.String())
	}
}

func TestAStoreFailureIsNotTakenForAMissingSession(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	boom := errors.New("database is down")
	f.breakSessions(func(s *sessionsFault) { s.resolveErr = boom })
	_, err := f.a.Authenticate(f.request(t, http.MethodGet, login, nil))
	if !errors.Is(err, boom) || errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate = %v, want the failure of the store and not ErrUnauthenticated", err)
	}
}

func TestCrossSiteCheckOfRequestsThatChangeData(t *testing.T) {
	spa := "https://spa.example.com"
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		tls     bool
		remote  string
		want    error
	}{
		{name: "a read needs no check", method: "GET"},
		{name: "a HEAD needs no check", method: "HEAD"},
		{name: "OPTIONS needs no check", method: "OPTIONS"},
		{name: "TRACE needs no check", method: "TRACE"},
		{name: "same origin", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}},
		{name: "PUT needs the check", method: "PUT", headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, want: ErrCSRF},
		{name: "PATCH needs the check", method: "PATCH", want: ErrCSRF},
		{name: "DELETE needs the check", method: "DELETE", want: ErrCSRF},
		{name: "no headers", method: "POST", want: ErrCSRF},
		{name: "no Origin", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, want: ErrCSRF},
		{name: "none is not same-origin", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "none"}, want: ErrCSRF},
		{name: "none with the Origin of the page", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "none", "Origin": "http://app.example.com"}},
		{name: "same-site with the Origin of the page", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://app.example.com"}},
		{name: "same-site from a sibling host", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://other.example.com"}, want: ErrCSRF},
		{name: "cross-site", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, want: ErrCSRF},
		{name: "an unknown value of Sec-Fetch-Site", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "Same-Origin"}, want: ErrCSRF},
		{name: "Origin of the page", method: "POST", headers: map[string]string{"Origin": "http://app.example.com"}},
		{name: "the host in upper case", method: "POST", headers: map[string]string{"Origin": "http://APP.Example.COM"}},
		{name: "the default port", method: "POST", headers: map[string]string{"Origin": "http://app.example.com:80"}},
		{name: "another port", method: "POST", headers: map[string]string{"Origin": "http://app.example.com:8080"}, want: ErrCSRF},
		{name: "another scheme", method: "POST", headers: map[string]string{"Origin": "https://app.example.com"}, want: ErrCSRF},
		{name: "another host", method: "POST", headers: map[string]string{"Origin": "http://app.example.org"}, want: ErrCSRF},
		{name: "a subdomain", method: "POST", headers: map[string]string{"Origin": "http://x.app.example.com"}, want: ErrCSRF},
		{name: "a longer host", method: "POST", headers: map[string]string{"Origin": "http://app.example.com.evil.example"}, want: ErrCSRF},
		{name: "null", method: "POST", headers: map[string]string{"Origin": "null"}, want: ErrCSRF},
		{name: "empty", method: "POST", headers: map[string]string{"Origin": ""}, want: ErrCSRF},
		{name: "with a path", method: "POST", headers: map[string]string{"Origin": "http://app.example.com/x"}, want: ErrCSRF},
		{name: "with a slash", method: "POST", headers: map[string]string{"Origin": "http://app.example.com/"}, want: ErrCSRF},
		{name: "with user info", method: "POST", headers: map[string]string{"Origin": "http://x@app.example.com"}, want: ErrCSRF},
		{name: "not an origin", method: "POST", headers: map[string]string{"Origin": "app.example.com"}, want: ErrCSRF},
		{name: "a trusted origin", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": spa}},
		{name: "a trusted origin in upper case", method: "POST", headers: map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "HTTPS://SPA.Example.com:443"}},
		{name: "a trusted host over http", method: "POST", headers: map[string]string{"Origin": "http://spa.example.com"}, want: ErrCSRF},
		{name: "a trusted origin with another port", method: "POST", headers: map[string]string{"Origin": "https://spa.example.com:8443"}, want: ErrCSRF},
		{name: "over TLS", method: "POST", tls: true, headers: map[string]string{"Origin": "https://app.example.com"}},
		{name: "over TLS the http origin is another one", method: "POST", tls: true, headers: map[string]string{"Origin": "http://app.example.com"}, want: ErrCSRF},
		{name: "forwarded https from a proxy", method: "POST", remote: "10.0.0.5:4000", headers: map[string]string{"X-Forwarded-Proto": "https", "Origin": "https://app.example.com"}},
		{name: "forwarded HTTPS in upper case", method: "POST", remote: "10.0.0.5:4000", headers: map[string]string{"X-Forwarded-Proto": " HTTPS ", "Origin": "https://app.example.com"}},
		{name: "forwarded https is not believed from a stranger", method: "POST", remote: "203.0.113.50:4000", headers: map[string]string{"X-Forwarded-Proto": "https", "Origin": "https://app.example.com"}, want: ErrCSRF},
		{name: "forwarded http from a proxy", method: "POST", remote: "10.0.0.5:4000", headers: map[string]string{"X-Forwarded-Proto": "http", "Origin": "http://app.example.com"}},
		{name: "a forwarded junk value", method: "POST", remote: "10.0.0.5:4000", headers: map[string]string{"X-Forwarded-Proto": "gopher", "Origin": "http://app.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSessionFixture(t, WithTrustedOrigins(spa), WithTrustedProxies(netip.MustParsePrefix("10.0.0.0/8")))
			login := f.login(t)
			headers := map[string]string{csrfHeader: login.CSRFToken}
			for name, value := range tc.headers {
				headers[name] = value
			}
			r := f.request(t, tc.method, login, headers)
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tc.remote != "" {
				r.RemoteAddr = tc.remote
			}
			if _, hasOrigin := tc.headers["Origin"]; hasOrigin && tc.headers["Origin"] == "" {
				r.Header["Origin"] = []string{""}
			}
			p, err := f.a.Authenticate(r)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Authenticate = %+v, %v; want %v", p, err, tc.want)
			}
			if tc.want != nil && p != (Principal{}) {
				t.Fatalf("a request that failed the check must not give a principal: %+v", p)
			}
		})
	}
}

func TestCSRFTokenIsRequiredAndBelongsToTheSession(t *testing.T) {
	f := newSessionFixture(t)
	mine, other := f.login(t), f.login(t)
	same := func(token string) map[string]string {
		return map[string]string{"Sec-Fetch-Site": "same-origin", csrfHeader: token}
	}
	cases := map[string]struct {
		headers map[string]string
		want    error
	}{
		"the right token":              {same(mine.CSRFToken), nil},
		"no token":                     {map[string]string{"Sec-Fetch-Site": "same-origin"}, ErrCSRF},
		"an empty token":               {same(""), ErrCSRF},
		"the token of another session": {same(other.CSRFToken), ErrCSRF},
		"the token cut short":          {same(mine.CSRFToken[:42]), ErrCSRF},
		"the session ID":               {same(mine.Principal.SessionID), ErrCSRF},
		"the secret of the cookie":     {same(mine.Secret), ErrCSRF},
		"the token in upper case":      {same(strings.ToUpper(mine.CSRFToken)), ErrCSRF},
	}
	for name, tc := range cases {
		r := f.request(t, http.MethodPost, mine, tc.headers)
		if _, err := f.a.Authenticate(r); !errors.Is(err, tc.want) {
			t.Errorf("%s: Authenticate = %v, want %v", name, err, tc.want)
		}
	}
	r := f.request(t, http.MethodPost, mine, nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Add(csrfHeader, other.CSRFToken)
	r.Header.Add(csrfHeader, mine.CSRFToken)
	if _, err := f.a.Authenticate(r); err != ErrCSRF { //nolint:errorlint
		t.Errorf("only the first token is looked at: %v, want ErrCSRF", err)
	}
}

func TestACrossSiteRequestIsRejectedBeforeTheSessionIsTrusted(t *testing.T) {
	f := newSessionFixture(t)
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
	login := f.login(t)
	headers := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example", csrfHeader: login.CSRFToken}
	p, err := f.a.Authenticate(f.request(t, http.MethodPost, login, headers))
	if err != ErrCSRF || p != (Principal{}) { //nolint:errorlint
		t.Fatalf("Authenticate = %+v, %v; want ErrCSRF and no principal", p, err)
	}
	p, err = f.a.Authenticate(f.request(t, http.MethodPost, login, f.sameOrigin(login)))
	if !errors.Is(err, ErrPasswordChangeRequired) || p != login.Principal {
		t.Fatalf("Authenticate = %+v, %v; want the principal with ErrPasswordChangeRequired", p, err)
	}
}

func TestDevelopmentModeUsesPlainCookieNames(t *testing.T) {
	logger, logs := capturingLogger()
	dev := newSessionFixture(t, WithDevelopmentMode(), WithLogger(logger))
	if dev.a.cookie != "limb_session" {
		t.Fatalf("cookie name = %q, want limb_session", dev.a.cookie)
	}
	if !strings.Contains(logs.String(), "development mode") {
		t.Fatalf("starting in development mode must be logged:\n%s", logs.String())
	}
	login := dev.login(t)
	if _, err := dev.a.Authenticate(dev.request(t, http.MethodGet, login, nil)); err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	prod, quiet := capturingLogger()
	secure := newSessionFixture(t, WithLogger(prod))
	if secure.a.cookie != "__Host-limb_session" || strings.Contains(quiet.String(), "development") {
		t.Fatalf("cookie name = %q, log = %s", secure.a.cookie, quiet.String())
	}
}

func TestParseOrigin(t *testing.T) {
	good := map[string]string{
		"https://app.example.com":       "https://app.example.com",
		"HTTPS://APP.Example.COM":       "https://app.example.com",
		"http://app.example.com:80":     "http://app.example.com",
		"https://app.example.com:443":   "https://app.example.com",
		"https://app.example.com:80":    "https://app.example.com:80",
		"http://app.example.com:443":    "http://app.example.com:443",
		"https://app.example.com:8443":  "https://app.example.com:8443",
		"http://localhost:3000":         "http://localhost:3000",
		"http://127.0.0.1:8080":         "http://127.0.0.1:8080",
		"http://[::1]:8080":             "http://[::1]:8080",
		"http://[2001:DB8::1]":          "http://[2001:db8::1]",
		"https://xn--e1afmkfd.xn--p1ai": "https://xn--e1afmkfd.xn--p1ai",
	}
	for in, want := range good {
		if got, ok := parseOrigin(in); !ok || got != want {
			t.Errorf("parseOrigin(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{
		"", " ", "null", "app.example.com", "//app.example.com", "ftp://app.example.com", "ws://app.example.com",
		"https://", "https:///", "https://app.example.com/", "https://app.example.com/path", "https://app.example.com?x=1",
		"https://app.example.com#top", "https://user@app.example.com", "https://user:pass@app.example.com",
		"https://app.example.com:0", "https://app.example.com:65536", "https://app.example.com:99999", "https://app.example.com:abc",
		"https://app.example.com:08080", "https://app.example.com:+80", " https://app.example.com", "https://app.example.com ",
		"https://app.example.com\n", "https://app .example.com", "mailto:a@example.com", "https:app.example.com", "https://[::1",
	} {
		if got, ok := parseOrigin(in); ok {
			t.Errorf("parseOrigin(%q) = %q, want a rejection", in, got)
		}
	}
}

func TestWithTrustedOriginsRejectsAnythingButOrigins(t *testing.T) {
	for _, bad := range []string{"", "spa.example.com", "https://spa.example.com/app", "https://spa.example.com/", "*"} {
		f := newFixtureErr(t, WithTrustedOrigins("https://ok.example.com", bad))
		if f == nil || !strings.Contains(f.Error(), "not an origin") || !strings.Contains(f.Error(), bad) {
			t.Errorf("%q: New = %v, want an error that names the value", bad, f)
		}
	}
	a, err := NewWithStore(newTestMemory(), []byte(testKey), WithAutoMigrate(), WithTrustedOrigins("HTTPS://SPA.example.com:443", "http://localhost:3000"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.origins["https://spa.example.com"]; !ok || len(a.origins) != 2 {
		t.Fatalf("origins = %v", a.origins)
	}
}

func TestWithSessionTTLValidatesItsArguments(t *testing.T) {
	cases := map[string][2]time.Duration{
		"short absolute": {30 * time.Second, 30 * time.Second},
		"short idle":     {time.Hour, 30 * time.Second},
		"zero":           {0, 0},
		"negative":       {-time.Hour, -time.Hour},
		"idle longer":    {time.Hour, 2 * time.Hour},
	}
	for name, ttl := range cases {
		if err := newFixtureErr(t, WithSessionTTL(ttl[0], ttl[1])); err == nil || !strings.HasPrefix(err.Error(), "limb: ") {
			t.Errorf("%s: New = %v, want a configuration error", name, err)
		}
	}
	f := newSessionFixture(t, WithSessionTTL(48*time.Hour, 6*time.Hour))
	login := f.login(t)
	s := f.session(t, login.Principal.SessionID).Session
	if got := s.ExpiresAt.Sub(s.CreatedAt); got != 48*time.Hour || f.a.idle != 6*time.Hour {
		t.Fatalf("absolute lifetime = %v, idle = %v", got, f.a.idle)
	}
	same := newSessionFixture(t, WithSessionTTL(time.Hour, time.Hour))
	if same.a.idle != time.Hour {
		t.Fatal("an idle lifetime equal to the absolute one is fine")
	}
	def := newSessionFixture(t)
	if def.a.absolute != 30*24*time.Hour || def.a.idle != 7*24*time.Hour {
		t.Fatalf("defaults = %v and %v, want 30 days and 7 days", def.a.absolute, def.a.idle)
	}
}

func TestSeveralOriginHeadersAreRefused(t *testing.T) {
	f := newSessionFixture(t)
	login := f.login(t)
	r := f.request(t, http.MethodPost, login, map[string]string{csrfHeader: login.CSRFToken})
	r.Header.Add("Origin", "http://app.example.com")
	r.Header.Add("Origin", "http://app.example.com")
	if _, err := f.a.Authenticate(r); err != ErrCSRF { //nolint:errorlint
		t.Fatalf("Authenticate = %v, want ErrCSRF: a request has one origin", err)
	}
}
