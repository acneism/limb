package limb

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/admin"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

type fuzzedAdmin struct {
	auth    *Auth
	handler http.Handler
	clock   *fakeClock
	seed    []byte
	client  admin.Client
	calls   int
}

func newFuzzedAdmin(f *testing.F, opts ...Option) *fuzzedAdmin {
	f.Helper()
	all := append([]Option{WithAutoMigrate(), WithLogger(discardingLogger()), WithAdminMountPath(adminMount), WithDevelopmentMode()}, opts...)
	a, err := NewWithStore(newTestMemory(), []byte(testKey), all...)
	if err != nil {
		f.Fatal(err)
	}
	a.hasher = newHasher(f, weakParams)
	clock := newFakeClock()
	a.now = clock.now
	ctx := context.Background()
	for _, login := range []string{adminLoginName, "fresh"} {
		if _, err = a.Admin().CreateAdmin(ctx, login, adminPassword); err != nil {
			f.Fatal(err)
		}
	}
	fz := &fuzzedAdmin{auth: a, handler: a.AdminHandler(), clock: clock, client: admin.Client{IP: "127.0.0.1", UserAgent: "fuzz"}}
	row := fz.row(f, adminLoginName)
	pending, err := a.admins.Begin(ctx, row, fz.client)
	if err != nil {
		f.Fatal(err)
	}
	in, err := a.admins.Pending(ctx, pending.Secret)
	if err != nil {
		f.Fatal(err)
	}
	enrollment, err := a.admins.Enroll(ctx, in)
	if err != nil {
		f.Fatal(err)
	}
	if in, err = a.admins.Pending(ctx, pending.Secret); err != nil {
		f.Fatal(err)
	}
	if _, _, err = a.admins.CompleteEnrollment(ctx, in, totp.Code(enrollment.Seed, totp.Step(clock.now())), fz.client); err != nil {
		f.Fatal(err)
	}
	fz.seed = enrollment.Seed
	return fz
}

func (fz *fuzzedAdmin) row(tb testing.TB, login string) store.Admin {
	tb.Helper()
	row, err := fz.auth.store.Admins().FindByLogin(context.Background(), fz.auth.tenant, login)
	if err != nil {
		tb.Fatal(err)
	}
	return row
}

func (fz *fuzzedAdmin) session(t *testing.T) (secret, token string) {
	t.Helper()
	ctx := context.Background()
	pending, err := fz.auth.admins.Begin(ctx, fz.row(t, adminLoginName), fz.client)
	if err != nil {
		t.Fatal(err)
	}
	in, err := fz.auth.admins.Pending(ctx, pending.Secret)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := fz.auth.admins.Complete(ctx, in, totp.Code(fz.seed, totp.Step(fz.clock.now())), fz.client)
	if err != nil {
		t.Fatal(err)
	}
	return opened.Secret, fz.auth.keys.CSRFToken("admin:" + opened.ID)
}

func (fz *fuzzedAdmin) pending(t *testing.T, login string) (secret, token string) {
	t.Helper()
	ctx := context.Background()
	pending, err := fz.auth.admins.Begin(ctx, fz.row(t, login), fz.client)
	if err != nil {
		t.Fatal(err)
	}
	in, err := fz.auth.admins.Pending(ctx, pending.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return pending.Secret, fz.auth.keys.CSRFToken("admin:" + in.Session.ID)
}

func FuzzAdminHandler(f *testing.F) {
	fz := newFuzzedAdmin(f)
	login := "login=root&password=" + url.QueryEscape(adminPassword)
	account := "current=" + url.QueryEscape(adminPassword) + "&new=a+new+password+to+choose&again=a+new+password+to+choose"
	const form = "application/x-www-form-urlencoded"
	for _, seed := range []struct {
		method, target, contentType, body, origin, fetchSite, cookie, language, forwarded string
		mode                                                                              uint8
		token                                                                             bool
	}{
		{"GET", "/login", "", "", "", "", "", "", "", 0, false},
		{"GET", "/", "", "", "", "", "", "ru-RU,ru;q=0.9", "", 0, false},
		{"GET", "/?lang=ru", "", "", "", "", "", "", "", 0, false},
		{"POST", "/login", form, login, fuzzOrigin, "", "", "", "", 0, false},
		{"POST", "/login", form, login, "", "same-origin", "", "", "203.0.113.9", 0, false},
		{"POST", "/login", form, "login=%FF&password=%00", fuzzOrigin, "", "", "", "", 0, false},
		{"POST", "/login", "application/json", `{"login":"root"}`, fuzzOrigin, "", "", "", "", 0, false},
		{"GET", "/", "", "", "", "", "", "", "", 1, false},
		{"GET", "/account?done=password", "", "", "", "", "", "", "", 1, false},
		{"POST", "/logout", form, "", fuzzOrigin, "", "", "", "", 1, true},
		{"POST", "/account/password", form, account, fuzzOrigin, "", "", "", "", 1, true},
		{"POST", "/account/password", form, "current=x&new=y&again=z", fuzzOrigin, "", "", "", "", 1, true},
		{"POST", "/account/recovery", form, "password=" + url.QueryEscape(adminPassword), fuzzOrigin, "", "", "", "", 1, true},
		{"POST", "/account/authenticator", form, "password=" + url.QueryEscape(adminPassword), fuzzOrigin, "", "", "", "", 1, true},
		{"POST", "/account/authenticator/confirm", form, "code=123456&token=x", fuzzOrigin, "", "", "", "", 1, true},
		{"POST", "/account/sessions/end", form, "session=x", fuzzOrigin, "", "", "", "", 1, true},
		{"POST", "/account/sessions/end-others", form, "", fuzzOrigin, "", "", "", "", 1, true},
		{"GET", "/login/code", "", "", "", "", "", "", "", 2, false},
		{"POST", "/login/code", form, "code=123456", fuzzOrigin, "", "", "", "", 2, true},
		{"POST", "/login/code", form, "code=" + strings.Repeat("9", 5000), fuzzOrigin, "", "", "", "", 2, true},
		{"GET", "/login/totp", "", "", "", "", "", "", "", 3, false},
		{"POST", "/login/totp", form, "code=123+456", fuzzOrigin, "", "", "", "", 3, true},
		{"GET", "/assets/admin.0000000000000000.css", "", "", "", "", "", "", "", 0, false},
		{"HEAD", "/login", "", "", "", "", "", "", "", 0, false},
		{"PROPFIND", "/a/b", "text/plain", "\x00", "null", "cross-site", "limb_admin=x; limb_admin_login=y", "\xff", "999.1.1.1, ::1", 1, false},
	} {
		f.Add(seed.method, seed.target, seed.contentType, seed.body, seed.origin, seed.fetchSite, seed.cookie, seed.language, seed.forwarded, seed.mode, seed.token)
	}
	f.Fuzz(func(t *testing.T, method, target, contentType, body, origin, fetchSite, cookie, language, forwarded string, mode uint8, withToken bool) {
		if !strings.HasPrefix(target, "/") || len(body) > 40<<10 || len(target) > 2000 {
			return
		}
		fz.clock.advance(16 * time.Minute)
		var sessionSecret, token string
		switch mode % 4 {
		case 1:
			sessionSecret, token = fz.session(t)
		case 2:
			sessionSecret, token = fz.pending(t, adminLoginName)
		case 3:
			sessionSecret, token = fz.pending(t, "fresh")
		}
		if withToken && token != "" {
			body += "&csrf=" + url.QueryEscape(token)
		}
		request, err := http.NewRequestWithContext(context.Background(), method, "http://app.example.com"+target, strings.NewReader(body))
		if err != nil {
			return
		}
		fz.calls++
		request.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1234", fz.calls>>16&255, fz.calls>>8&255, fz.calls&255)
		cookies := cookie
		switch mode % 4 {
		case 1:
			cookies = "limb_admin=" + sessionSecret + "; " + cookies
		case 2, 3:
			cookies = "limb_admin_login=" + sessionSecret + "; " + cookies
		}
		for name, value := range map[string]string{
			"Content-Type": contentType, "Origin": origin, "Sec-Fetch-Site": fetchSite, "Cookie": cookies, "Accept-Language": language, "X-Forwarded-For": forwarded,
		} {
			if value != "" {
				request.Header.Set(name, value)
			}
		}
		recorder := httptest.NewRecorder()
		fz.handler.ServeHTTP(recorder, request)
		checkFuzzedAdminAnswer(t, recorder, method, target, sessionSecret)
	})
}

const fuzzOrigin = "http://app.example.com"

func checkFuzzedAdminAnswer(t *testing.T, recorder *httptest.ResponseRecorder, method, target, secret string) {
	t.Helper()
	if recorder.Code >= http.StatusInternalServerError {
		t.Fatalf("%s %q answered %d: %.300s", method, target, recorder.Code, recorder.Body.String())
	}
	header := recorder.Header()
	if header.Get("Content-Security-Policy") != adminContentSecurityPolicy || header.Get("X-Frame-Options") != "DENY" || header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%s %q answered %d without the security headers: %v", method, target, recorder.Code, header)
	}
	asset := recorder.Code == http.StatusOK && strings.HasPrefix(header.Get("Content-Type"), "text/css")
	if cache := header.Get("Cache-Control"); cache != "no-store" && (!asset || cache != "public, max-age=31536000, immutable") {
		t.Fatalf("%s %q answered %d with Cache-Control %q", method, target, recorder.Code, cache)
	}
	if recorder.Code < http.StatusMultipleChoices || recorder.Code >= http.StatusBadRequest {
		if contentType := header.Get("Content-Type"); contentType != "text/html; charset=utf-8" && !asset && recorder.Body.Len() > 0 {
			t.Fatalf("%s %q answered %d with the content type %q", method, target, recorder.Code, contentType)
		}
	}
	if location := header.Get("Location"); location != "" && (!strings.HasPrefix(location, adminMount) || strings.HasPrefix(location, "//") || strings.ContainsAny(location, "\r\n")) {
		t.Fatalf("%s %q redirects to %q", method, target, location)
	}
	for _, cookie := range recorder.Result().Cookies() {
		switch cookie.Name {
		case webSessionCookie:
			if cookie.Value != "" {
				t.Fatalf("%s %q set a session without the second step", method, target)
			}
		case webLanguageCookie:
			if cookie.Value != "en" && cookie.Value != "ru" {
				t.Fatalf("%s %q set the language %q", method, target, cookie.Value)
			}
		}
	}
	body := recorder.Body.String()
	if strings.Contains(strings.ToLower(body), "<script") || strings.Contains(body, adminPassword) || (secret != "" && strings.Contains(body, secret)) {
		t.Fatalf("%s %q answered with a script, a password or a secret: %.300s", method, target, body)
	}
}
