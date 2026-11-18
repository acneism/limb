package limb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/acneism/limb/internal/adminui"
	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/internal/totp"
)

func TestAdminHandlerPanicsWithoutAMountPath(t *testing.T) {
	a := newTestAuth(t)
	defer func() {
		message, _ := recover().(string)
		if !strings.Contains(message, "WithAdminMountPath") || !strings.Contains(message, "cookies") {
			t.Fatalf("AdminHandler panicked with %q, want a message that says what to do", message)
		}
	}()
	a.AdminHandler()
	t.Fatal("AdminHandler did not panic without a mount path")
}

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	f := newWebFixture(t)
	want := map[string]string{
		"Content-Security-Policy":      "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; style-src 'self'",
		"X-Frame-Options":              "DENY",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Cache-Control":                "no-store",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Robots-Tag":                 "noindex, nofollow",
	}
	wrong := url.Values{"login": {adminLoginName}, "password": {"not the password"}}
	responses := map[string]webResponse{
		"the sign-in page":             f.get("/login"),
		"a page that is not there":     f.get("/nowhere"),
		"a method that is not allowed": f.post("/", url.Values{}),
		"a redirect":                   f.get("/"),
		"a form that is refused":       f.post("/login", wrong, "Origin", "https://evil.example"),
		"a sign-in that failed":        f.post("/login", wrong),
	}
	for name, r := range responses {
		for header, value := range want {
			if got := r.Header.Get(header); got != value {
				t.Errorf("%s: %s is %q, want %q", name, header, got, value)
			}
		}
		if got := r.Header.Get("Permissions-Policy"); !strings.Contains(got, "camera=()") || !strings.Contains(got, "geolocation=()") || !strings.Contains(got, "microphone=()") {
			t.Errorf("%s: Permissions-Policy is %q", name, got)
		}
		if r.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: the development mode sends Strict-Transport-Security", name)
		}
		if r.StatusCode != http.StatusSeeOther && r.Header.Get("Content-Type") != "text/html; charset=utf-8" {
			t.Errorf("%s: the content type is %q", name, r.Header.Get("Content-Type"))
		}
	}

	secure := newTestAuth(t, WithAdminMountPath(adminMount))
	rec := httptest.NewRecorder()
	secure.AdminHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Fatalf("Strict-Transport-Security is %q outside the development mode", got)
	}
}

func TestTheStylesheetIsServedUnderItsHashAndKeptForGood(t *testing.T) {
	f := newWebFixture(t)
	page := f.get("/login")
	link := `href="` + adminMount + `/assets/` + adminui.StylesheetName() + `"`
	if !page.has(link) {
		t.Fatalf("the page does not link the stylesheet with %s: %.400s", link, page.body)
	}
	css := f.get("/assets/" + adminui.StylesheetName())
	if css.StatusCode != http.StatusOK || css.Header.Get("Content-Type") != "text/css; charset=utf-8" ||
		css.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" || css.Header.Get("X-Content-Type-Options") != "nosniff" ||
		css.Header.Get("Content-Length") != strconv.Itoa(len(adminui.Stylesheet())) || css.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("the stylesheet is %d with %v", css.StatusCode, css.Header)
	}
	if css.body != string(adminui.Stylesheet()) || len(css.Cookies()) != 0 {
		t.Fatalf("the stylesheet is not the embedded one or sets cookies: %.80q", css.body)
	}
	if page.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("a page may be kept")
	}
	if head := f.request(http.MethodHead, "/assets/"+adminui.StylesheetName()); head.StatusCode != http.StatusOK || head.body != "" {
		t.Fatalf("HEAD of the stylesheet is %d with %d bytes", head.StatusCode, len(head.body))
	}
	if other := f.get("/assets/admin.0000000000000000.css"); other.StatusCode != http.StatusNotFound || other.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("a stylesheet under another hash is %d with %q", other.StatusCode, other.Header.Get("Cache-Control"))
	}
	if post := f.post("/assets/"+adminui.StylesheetName(), url.Values{}); post.StatusCode != http.StatusMethodNotAllowed || post.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST to the stylesheet is %d with Allow %q", post.StatusCode, post.Header.Get("Allow"))
	}
}

func TestAPageThatIsNotThereOrIsUsedTheWrongWayIsRefusedAsAPage(t *testing.T) {
	f := newWebFixture(t)
	for _, path := range []string{"/nowhere", "/login/", "/login/code/", "//login", "/Login", "/login/other", "/assets/", "/logout/x", "/account", "/users"} {
		if r := f.get(path); r.StatusCode != http.StatusNotFound || !r.has("Page not found") || !r.has("There is nothing at this address.") {
			t.Errorf("GET %s = %d", path, r.StatusCode)
		}
	}
	for _, c := range []struct{ method, path, allow string }{
		{http.MethodPut, "/", "GET, HEAD"},
		{http.MethodPost, "/", "GET, HEAD"},
		{http.MethodDelete, "/", "GET, HEAD"},
		{http.MethodPut, "/login", "GET, HEAD, POST"},
		{http.MethodDelete, "/login", "GET, HEAD, POST"},
		{http.MethodPatch, "/login/code", "GET, HEAD, POST"},
		{http.MethodPut, "/login/totp", "GET, HEAD, POST"},
		{http.MethodGet, "/logout", "POST"},
		{http.MethodDelete, "/logout", "POST"},
	} {
		r := f.request(c.method, c.path)
		if r.StatusCode != http.StatusMethodNotAllowed || r.Header.Get("Allow") != c.allow || !r.has("This method is not allowed") {
			t.Errorf("%s %s = %d with Allow %q, want 405 and %q", c.method, c.path, r.StatusCode, r.Header.Get("Allow"), c.allow)
		}
	}
	if r := f.request(http.MethodHead, "/login"); r.StatusCode != http.StatusOK || r.body != "" {
		t.Errorf("HEAD /login = %d with %d bytes", r.StatusCode, len(r.body))
	}
	if r := f.get(""); r.StatusCode != http.StatusSeeOther || r.location() != adminMount+"/login" {
		t.Errorf("the mount path itself is %d %q", r.StatusCode, r.location())
	}
}

func TestAFormMustComeFromAPageOfTheApplicationAndBeAFormOfASaneSize(t *testing.T) {
	f := newWebFixture(t)
	form := url.Values{"login": {adminLoginName}, "password": {adminPassword}}
	refused := []struct {
		name    string
		headers []string
	}{
		{"another origin", []string{"Origin", "https://evil.example"}},
		{"an origin that is null", []string{"Origin", "null"}},
		{"another scheme", []string{"Origin", strings.Replace(f.server.URL, "http://", "https://", 1)}},
		{"another port", []string{"Origin", "http://127.0.0.1:1"}},
		{"no origin and no fetch metadata", []string{"Origin", ""}},
		{"a fetch from another site", []string{"Sec-Fetch-Site", "cross-site"}},
		{"a fetch from the same site", []string{"Sec-Fetch-Site", "same-site"}},
		{"a fetch from nowhere", []string{"Sec-Fetch-Site", "none"}},
		{"a fetch from another site with the right origin", []string{"Sec-Fetch-Site", "cross-site", "Origin", f.server.URL}},
	}
	for _, c := range refused {
		r := f.post("/login", form, c.headers...)
		if r.StatusCode != http.StatusForbidden || !r.has("It did not come from a page of this site") || f.cookie(webPendingCookie) != nil {
			t.Errorf("%s: the form gave %d", c.name, r.StatusCode)
		}
	}

	two, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.url("/login"), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	two.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	two.Header.Add("Origin", f.server.URL)
	two.Header.Add("Origin", "https://evil.example")
	if r := f.do(two); r.StatusCode != http.StatusForbidden {
		t.Errorf("two origins gave %d", r.StatusCode)
	}

	for name, contentType := range map[string]string{"JSON": "application/json", "multipart": "multipart/form-data; boundary=x", "text": "text/plain", "nothing": ""} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.url("/login"), strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", f.server.URL)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if r := f.do(req); r.StatusCode != http.StatusUnsupportedMediaType || !r.has("The form is not in the expected format") {
			t.Errorf("%s: the form gave %d", name, r.StatusCode)
		}
	}

	big := url.Values{"login": {adminLoginName}, "password": {strings.Repeat("a", maxAdminForm)}}
	if r := f.post("/login", big); r.StatusCode != http.StatusRequestEntityTooLarge || !r.has("The request is too large") {
		t.Errorf("a form of more than %d bytes gave %d", maxAdminForm, r.StatusCode)
	}
	if got := len(f.records(audit.AdminLoginFailed)); got != 0 {
		t.Errorf("%d failures were recorded for forms that were refused before the password was looked at", got)
	}

	f.browser = f.newBrowser()
	if r := f.post("/login", form, "Sec-Fetch-Site", "same-origin", "Origin", ""); r.StatusCode != http.StatusSeeOther {
		t.Errorf("a fetch from the same origin without an Origin header gave %d", r.StatusCode)
	}
	f.browser = f.newBrowser()
	if r := f.post("/login", form, "Sec-Fetch-Site", "same-origin", "Origin", "https://evil.example"); r.StatusCode != http.StatusSeeOther {
		t.Errorf("a fetch from the same origin, which the browser vouches for, gave %d", r.StatusCode)
	}
}

func TestTheLanguageIsTheOneOfTheBrowserOrTheOneTheAdministratorChose(t *testing.T) {
	f := newWebFixture(t)
	english := f.get("/login")
	if !english.has(`<html lang="en">`) || !english.has("Sign in") || !english.has(`href="?lang=ru"`) || !english.has(`<span aria-current="true">English</span>`) {
		t.Fatalf("the page without a preference is not English with a link to Russian: %.600s", english.body)
	}
	russian := f.get("/login", "Accept-Language", "ru-RU,ru;q=0.9,en;q=0.8")
	if !russian.has(`<html lang="ru">`) || !russian.has("Вход") || !russian.has(`href="?lang=en"`) {
		t.Fatalf("the page for a Russian browser is not Russian: %.600s", russian.body)
	}
	if other := f.get("/login", "Accept-Language", "de,fr;q=0.8"); !other.has(`<html lang="en">`) {
		t.Fatal("a language that there is no text for did not give English")
	}
	if weighted := f.get("/login", "Accept-Language", "ru;q=0.2,en;q=0.9"); !weighted.has(`<html lang="en">`) {
		t.Fatal("the weights of the languages were not taken into account")
	}

	switched := f.get("/login?lang=ru")
	cookie := switched.cookie(webLanguageCookie)
	if switched.StatusCode != http.StatusSeeOther || switched.location() != adminMount+"/login" || cookie == nil || cookie.Value != "ru" ||
		cookie.Path != adminMount+"/" || !cookie.HttpOnly || cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 365*24*60*60 {
		t.Fatalf("the choice of Russian gave %d %q with %+v", switched.StatusCode, switched.location(), cookie)
	}
	if page := f.get("/login", "Accept-Language", "en"); !page.has(`<html lang="ru">`) || !page.has("Вход") {
		t.Fatalf("the choice of the administrator did not win over the browser: %.300s", page.body)
	}
	if wrong := f.post("/login", url.Values{"login": {adminLoginName}, "password": {"x"}}); !wrong.has("Неверный логин или пароль.") {
		t.Fatal("the error is not in the language of the administrator")
	}
	if missing := f.get("/nowhere"); !missing.has("Страница не найдена") {
		t.Fatal("the page that is not there is not in the language of the administrator")
	}
	f.get("/login?lang=en")
	if page := f.get("/login"); !page.has(`<html lang="en">`) {
		t.Fatal("the language could not be changed back")
	}

	for _, query := range []string{"?lang=xx", "?lang=ru&lang=en", "?lang=", "?lang=RU", "?lang=ru-RU", "?lang=../ru", "?lang=" + url.QueryEscape("ru\r\nSet-Cookie: a=b")} {
		f.browser = f.newBrowser()
		r := f.get("/login" + query)
		if r.StatusCode != http.StatusOK || r.cookie(webLanguageCookie) != nil || !r.has(`<html lang="en">`) {
			t.Errorf("%s gave %d and a cookie %v", query, r.StatusCode, r.cookie(webLanguageCookie))
		}
	}
	f.browser = f.newBrowser()
	if r := f.post("/login?lang=ru", url.Values{"login": {adminLoginName}, "password": {"x"}}); r.StatusCode != http.StatusUnauthorized || r.cookie(webLanguageCookie) != nil {
		t.Errorf("a form sent with a language in the query gave %d and a cookie %v", r.StatusCode, r.cookie(webLanguageCookie))
	}
	f.setCookie(webLanguageCookie, "xx", adminMount+"/")
	if r := f.get("/login", "Accept-Language", "ru"); !r.has(`<html lang="ru">`) {
		t.Error("a language in the cookie that there is no text for did not fall back to the browser")
	}
	if r := f.get("/?lang=ru"); r.location() != adminMount+"/" {
		t.Errorf("the language chosen on the first page sends to %q", r.location())
	}
}

func TestTheApplicationAddsALanguageAndChangesTextsOfItsOwn(t *testing.T) {
	f := newWebFixture(t,
		WithAdminTexts("de", map[string]string{"login.title": "Anmelden", "error.404": "Seite nicht gefunden"}),
		WithAdminTexts("ru", map[string]string{"login.title": "Вход для сотрудников"}),
		WithAdminTexts("en", map[string]string{"login.submit": "Go on"}),
	)
	german := f.get("/login", "Accept-Language", "de-DE,de;q=0.9")
	if !german.has(`<html lang="de">`) || !german.has("Anmelden") || !german.has("Password") {
		t.Fatalf("the page in the language that was added is wrong: %.800s", german.body)
	}
	if missing := f.get("/nowhere", "Accept-Language", "de"); !missing.has("Seite nicht gefunden") || !missing.has("There is nothing at this address.") {
		t.Fatal("the language that was added did not use its text and the English one for the rest")
	}
	if ru := f.get("/login", "Accept-Language", "ru"); !ru.has("Вход для сотрудников") || !ru.has("Пароль") {
		t.Fatal("a text of Russian was not replaced, or the others were lost")
	}
	if en := f.get("/login"); !en.has("Go on") || !en.has("Sign in") || !en.has(`href="?lang=de"`) {
		t.Fatal("a text of English was not replaced, or the new language is not offered")
	}
}

func TestOnlyTheAddressesOfTheListGetPages(t *testing.T) {
	a, _ := newLimitedAuth(t, WithAdminMountPath(adminMount), WithDevelopmentMode(),
		WithAdminIPs(netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")))
	h := a.AdminHandler()
	serve := func(method, remote, path string, body *strings.Reader, headers ...string) *httptest.ResponseRecorder {
		var req *http.Request
		if body == nil {
			req = httptest.NewRequestWithContext(t.Context(), method, path, nil)
		} else {
			req = httptest.NewRequestWithContext(t.Context(), method, path, body)
		}
		req.RemoteAddr = remote
		setHeaders(req, headers)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for remote, allowed := range map[string]bool{
		"203.0.113.9:1234":        true,
		"203.0.113.255:1":         true,
		"203.0.114.9:1234":        false,
		"203.0.112.255:1234":      false,
		"[2001:db8::7]:80":        true,
		"[2001:db8:ffff::1]:80":   true,
		"[2001:db9::7]:80":        false,
		"[::ffff:203.0.113.9]:80": true,
		"198.51.100.1:5":          false,
		"127.0.0.1:5":             false,
		"":                        false,
		"not an address":          false,
	} {
		if rec := serve(http.MethodGet, remote, "/login", nil); (rec.Code == http.StatusOK) != allowed {
			t.Errorf("%q: the answer is %d, want a page for %v", remote, rec.Code, allowed)
		}
	}

	denied := serve(http.MethodGet, "198.51.100.1:5", "/login", nil)
	absent := serve(http.MethodGet, "203.0.113.9:1", "/not/a/page", nil)
	if denied.Code != http.StatusNotFound || denied.Body.String() != absent.Body.String() || denied.Header().Get("Content-Type") != absent.Header().Get("Content-Type") ||
		len(denied.Result().Cookies()) != 0 {
		t.Fatalf("an address that is not on the list gets %d with %d bytes, a page that is not there %d with %d: they must be the same", denied.Code, denied.Body.Len(), absent.Code, absent.Body.Len())
	}
	form := url.Values{"login": {adminLoginName}, "password": {adminPassword}}.Encode()
	post := serve(http.MethodPost, "198.51.100.1:5", "/login", strings.NewReader(form), "Content-Type", "application/x-www-form-urlencoded", "Sec-Fetch-Site", "same-origin")
	if post.Code != http.StatusNotFound || len(post.Result().Cookies()) != 0 {
		t.Fatalf("a sign-in from an address that is not on the list gave %d", post.Code)
	}
	if asset := serve(http.MethodGet, "198.51.100.1:5", "/assets/"+adminui.StylesheetName(), nil); asset.Code != http.StatusNotFound {
		t.Fatalf("the stylesheet for an address that is not on the list gave %d", asset.Code)
	}
	if got := len(recordsOf(t, a, audit.AdminLoginFailed)); got != 0 {
		t.Fatalf("%d failures were recorded for requests that were turned away at the door", got)
	}
}

func TestTheClientIsTheOneThatATrustedProxyTellsOf(t *testing.T) {
	a, _ := newLimitedAuth(t, WithAdminMountPath(adminMount), WithDevelopmentMode(),
		WithAdminIPs(netip.MustParsePrefix("203.0.113.0/24")), WithTrustedProxies(netip.MustParsePrefix("10.0.0.0/8")))
	h := a.AdminHandler()
	ask := func(remote, forwarded string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil)
		req.RemoteAddr = remote
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		name, remote, forwarded string
		want                    int
	}{
		{"a client that a proxy vouches for", "10.1.2.3:80", "203.0.113.9", http.StatusOK},
		{"a client outside the list that a proxy vouches for", "10.1.2.3:80", "198.51.100.9", http.StatusNotFound},
		{"a client that vouches for itself", "198.51.100.9:80", "203.0.113.9", http.StatusNotFound},
		{"a chain that ends outside the list", "10.1.2.3:80", "203.0.113.9, 198.51.100.9", http.StatusNotFound},
		{"a chain of proxies that ends inside it", "10.1.2.3:80", "198.51.100.9, 203.0.113.9, 10.9.9.9", http.StatusOK},
		{"a proxy that tells nothing", "10.1.2.3:80", "", http.StatusNotFound},
		{"a proxy that tells something that is not an address", "10.1.2.3:80", "203.0.113.9, nonsense", http.StatusNotFound},
	} {
		if got := ask(c.remote, c.forwarded); got != c.want {
			t.Errorf("%s: the answer is %d, want %d", c.name, got, c.want)
		}
	}
}

func TestTheCookiesOfTheDevelopmentModeAndOfProductionAreSetApart(t *testing.T) {
	cases := []struct {
		name                     string
		development              bool
		sessionName, pendingName string
		otherName                string
	}{
		{"development", true, webSessionCookie, webPendingCookie, "__Secure-" + webSessionCookie},
		{"production", false, "__Secure-" + webSessionCookie, "__Secure-" + webPendingCookie, webSessionCookie},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := []Option{WithAdminMountPath("/ops/admin")}
			if c.development {
				opts = append(opts, WithDevelopmentMode())
			}
			a, clock := newLimitedAuth(t, opts...)
			if _, err := a.Admin().CreateAdmin(t.Context(), adminLoginName, adminPassword); err != nil {
				t.Fatal(err)
			}
			h := a.AdminHandler()
			serve := func(method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				var req *http.Request
				if form == nil {
					req = httptest.NewRequestWithContext(t.Context(), method, path, nil)
				} else {
					req = httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(form.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Set("Sec-Fetch-Site", "same-origin")
				}
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				return rec
			}
			first := serve(http.MethodPost, "/login", url.Values{"login": {adminLoginName}, "password": {adminPassword}})
			cookies := first.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != c.pendingName {
				t.Fatalf("the cookies of the password are %v, want %s", cookies, c.pendingName)
			}
			pending := cookies[0]
			if pending.Path != "/ops/admin/login" || !pending.HttpOnly || pending.Secure != !c.development || pending.SameSite != http.SameSiteStrictMode ||
				pending.MaxAge != 5*60 || len(pending.Value) != secret.TextLen {
				t.Fatalf("the cookie of the second step is %+v", pending)
			}
			page := serve(http.MethodGet, "/login/totp", nil, pending)
			found, err := a.store.Admins().FindByLogin(t.Context(), a.tenant, adminLoginName)
			if err != nil {
				t.Fatal(err)
			}
			seed, err := a.keys.OpenTOTP(found.TOTPSecret, found.ID)
			if err != nil {
				t.Fatal(err)
			}
			match := csrfPattern.FindStringSubmatch(page.Body.String())
			if match == nil {
				t.Fatalf("the page has no token: %.300s", page.Body.String())
			}
			done := serve(http.MethodPost, "/login/totp", url.Values{"code": {totp.Code(seed, totp.Step(clock.now()))}, "csrf": {match[1]}}, pending)
			var session, cleared *http.Cookie
			for _, cookie := range done.Result().Cookies() {
				switch cookie.Name {
				case c.sessionName:
					session = cookie
				case c.pendingName:
					cleared = cookie
				}
			}
			if session == nil || session.Path != "/ops/admin/" || !session.HttpOnly || session.Secure != !c.development || session.SameSite != http.SameSiteStrictMode ||
				session.MaxAge != 0 || !session.Expires.IsZero() || len(session.Value) != secret.TextLen || session.Value == pending.Value {
				t.Fatalf("the cookie of the session is %+v, want a cookie of the browser session scoped to the mount path", session)
			}
			if cleared == nil || cleared.MaxAge >= 0 || cleared.Path != "/ops/admin/login" || cleared.Value != "" || cleared.Secure != !c.development {
				t.Fatalf("the cookie of the second step was left as %+v", cleared)
			}
			if home := serve(http.MethodGet, "/", nil, session); home.Code != http.StatusOK {
				t.Fatalf("the session of the cookie gave %d", home.Code)
			}
			other := &http.Cookie{Name: c.otherName, Value: session.Value} //nolint:gosec
			if home := serve(http.MethodGet, "/", nil, other); home.Code != http.StatusSeeOther {
				t.Fatalf("the session under the name of the other mode gave %d: the name tells the mode apart", home.Code)
			}
		})
	}
}

type panickingHasher struct{ passwordHasher }

func (panickingHasher) Verify(context.Context, string, string) (bool, bool, error) {
	panic("the hasher fell over with a value of the user")
}

func TestAPageThatPanicsIsAnErrorPageAndTheLogDoesNotHoldTheValue(t *testing.T) {
	logger, logs := capturingLogger()
	a, clock := newLimitedAuth(t, WithAdminMountPath(adminMount), WithDevelopmentMode(), WithLogger(logger))
	a.hasher = panickingHasher{a.hasher}
	f := startWebFixture(t, a, clock)
	r := f.password()
	if r.StatusCode != http.StatusInternalServerError || !r.has("Something went wrong") || r.has("fell over") ||
		r.Header.Get("Content-Security-Policy") == "" || len(r.Cookies()) != 0 {
		t.Fatalf("a panic gave %d: %.300s", r.StatusCode, r.body)
	}
	if text := logs.String(); !strings.Contains(text, "a page of the administration panicked") || !strings.Contains(text, "panic_type=string") || strings.Contains(text, "fell over") {
		t.Fatalf("the log of the panic is %q", text)
	}
	if next := f.get("/login"); next.StatusCode != http.StatusOK {
		t.Fatalf("the page after a panic is %d", next.StatusCode)
	}
}
