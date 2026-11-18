package limb

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

const (
	adminMount        = "/admin"
	adminLoginName    = "root"
	webPendingCookie  = "limb_admin_login"
	webSessionCookie  = "limb_admin"
	webLanguageCookie = "limb_admin_lang"
)

var (
	csrfPattern     = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	recoveryPattern = regexp.MustCompile(`<code>([A-Z2-7-]+)</code>`)
)

type webFixture struct {
	*browser
	t      *testing.T
	a      *Auth
	clock  *fakeClock
	server *httptest.Server
}

type browser struct {
	f      *webFixture
	client *http.Client
	jar    *cookiejar.Jar
}

type webResponse struct {
	*http.Response
	body string
}

func (r webResponse) location() string {
	return r.Header.Get("Location")
}

func (r webResponse) has(text string) bool {
	return strings.Contains(r.body, text)
}

func (r webResponse) cookie(name string) *http.Cookie {
	for _, c := range r.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func newWebFixture(t *testing.T, opts ...Option) *webFixture {
	t.Helper()
	all := append([]Option{WithAdminMountPath(adminMount), WithDevelopmentMode()}, opts...)
	a, clock := newLimitedAuth(t, all...)
	return startWebFixture(t, a, clock)
}

func serveWeb(t *testing.T, a *Auth, clock *fakeClock) *webFixture {
	t.Helper()
	f := &webFixture{t: t, a: a, clock: clock}
	f.server = httptest.NewServer(http.StripPrefix(adminMount, a.AdminHandler()))
	t.Cleanup(f.server.Close)
	f.browser = f.newBrowser()
	return f
}

func startWebFixture(t *testing.T, a *Auth, clock *fakeClock) *webFixture {
	t.Helper()
	f := serveWeb(t, a, clock)
	if _, err := a.Admin().CreateAdmin(t.Context(), adminLoginName, adminPassword); err != nil {
		t.Fatalf("CreateAdmin failed: %v", err)
	}
	return f
}

func (f *webFixture) newBrowser() *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return &browser{f: f, jar: jar, client: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) url(path string) string {
	return b.f.server.URL + adminMount + path
}

func (b *browser) do(req *http.Request) webResponse {
	b.f.t.Helper()
	response, err := b.client.Do(req)
	if err != nil {
		b.f.t.Fatalf("%s %s failed: %v", req.Method, req.URL, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		b.f.t.Fatalf("reading the answer to %s %s failed: %v", req.Method, req.URL, err)
	}
	return webResponse{Response: response, body: string(body)}
}

func setHeaders(req *http.Request, headers []string) {
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i+1] == "" {
			req.Header.Del(headers[i])
		} else {
			req.Header.Set(headers[i], headers[i+1])
		}
	}
}

func (b *browser) request(method, path string, headers ...string) webResponse {
	b.f.t.Helper()
	req, err := http.NewRequestWithContext(b.f.t.Context(), method, b.url(path), nil)
	if err != nil {
		b.f.t.Fatal(err)
	}
	setHeaders(req, headers)
	return b.do(req)
}

func (b *browser) get(path string, headers ...string) webResponse {
	b.f.t.Helper()
	return b.request(http.MethodGet, path, headers...)
}

func (b *browser) post(path string, form url.Values, headers ...string) webResponse {
	b.f.t.Helper()
	req, err := http.NewRequestWithContext(b.f.t.Context(), http.MethodPost, b.url(path), strings.NewReader(form.Encode()))
	if err != nil {
		b.f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.f.server.URL)
	setHeaders(req, headers)
	return b.do(req)
}

func (b *browser) postStatus(path string, form url.Values) (int, error) {
	req, err := http.NewRequestWithContext(b.f.t.Context(), http.MethodPost, b.url(path), strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.f.server.URL)
	response, err := b.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		return 0, err
	}
	return response.StatusCode, nil
}

func (b *browser) cookie(name string) *http.Cookie {
	b.f.t.Helper()
	u, err := url.Parse(b.url("/login/code"))
	if err != nil {
		b.f.t.Fatal(err)
	}
	for _, c := range b.jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (b *browser) setCookie(name, value, path string) {
	b.f.t.Helper()
	u, err := url.Parse(b.url("/"))
	if err != nil {
		b.f.t.Fatal(err)
	}
	b.jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value, Path: path}}) //nolint:gosec
}

func (b *browser) csrfOf(page webResponse) string {
	b.f.t.Helper()
	match := csrfPattern.FindStringSubmatch(page.body)
	if match == nil {
		b.f.t.Fatalf("the page has no token: %.300s", page.body)
	}
	return match[1]
}

func (b *browser) password() webResponse {
	b.f.t.Helper()
	return b.post("/login", url.Values{"login": {adminLoginName}, "password": {adminPassword}})
}

func (b *browser) enroll() []string {
	b.f.t.Helper()
	if r := b.password(); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login/totp" {
		b.f.t.Fatalf("the password gave %d %q, want a redirect to the binding of an authenticator", r.StatusCode, r.location())
	}
	page := b.get("/login/totp")
	if page.StatusCode != http.StatusOK {
		b.f.t.Fatalf("the page of the binding is %d", page.StatusCode)
	}
	done := b.post("/login/totp", url.Values{"code": {b.f.code()}, "csrf": {b.csrfOf(page)}})
	if done.StatusCode != http.StatusOK || !done.has("<code>") {
		b.f.t.Fatalf("the binding gave %d: %.300s", done.StatusCode, done.body)
	}
	var codes []string
	for _, m := range recoveryPattern.FindAllStringSubmatch(done.body, -1) {
		codes = append(codes, m[1])
	}
	b.f.clock.advance(totp.StepSeconds * time.Second)
	return codes
}

func (b *browser) signIn() webResponse {
	b.f.t.Helper()
	if r := b.password(); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login/code" {
		b.f.t.Fatalf("the password gave %d %q, want a redirect to the second step", r.StatusCode, r.location())
	}
	page := b.get("/login/code")
	if page.StatusCode != http.StatusOK {
		b.f.t.Fatalf("the page of the second step is %d", page.StatusCode)
	}
	return b.post("/login/code", url.Values{"code": {b.f.code()}, "csrf": {b.csrfOf(page)}})
}

func (b *browser) signInAgain() webResponse {
	b.f.t.Helper()
	b.f.clock.advance(totp.StepSeconds * time.Second)
	return b.signIn()
}

func (f *webFixture) seed() []byte {
	f.t.Helper()
	found, err := f.a.store.Admins().FindByLogin(f.t.Context(), f.a.tenant, adminLoginName)
	if err != nil {
		f.t.Fatal(err)
	}
	seed, err := f.a.keys.OpenTOTP(found.TOTPSecret, found.ID)
	if err != nil {
		f.t.Fatalf("the seed of the authenticator cannot be opened: %v", err)
	}
	return seed
}

func (f *webFixture) code() string {
	f.t.Helper()
	return totp.Code(f.seed(), totp.Step(f.clock.now()))
}

func (f *webFixture) wrongCode() string {
	f.t.Helper()
	seed, step := f.seed(), totp.Step(f.clock.now())
	valid := map[string]bool{}
	for offset := int64(-totp.Window); offset <= totp.Window; offset++ {
		valid[totp.Code(seed, step+offset)] = true
	}
	for n := 0; ; n++ {
		if candidate := fmt.Sprintf("%0*d", totp.Digits, n); !valid[candidate] {
			return candidate
		}
	}
}

func (f *webFixture) records(action string) []store.AuditRecord {
	f.t.Helper()
	return recordsOf(f.t, f.a, action)
}

func (f *webFixture) failures(stage, reason string) []store.AuditRecord {
	f.t.Helper()
	var found []store.AuditRecord
	for _, r := range f.records(audit.AdminLoginFailed) {
		details := detailsOf(f.t, r)
		if details["stage"] == stage && details["reason"] == reason {
			found = append(found, r)
		}
	}
	return found
}
