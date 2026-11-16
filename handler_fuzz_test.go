package limb

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type fuzzedAPI struct {
	plain, jar http.Handler
	cookie     string
	csrf       string
	access     string
	refresh    string
}

func newFuzzedAPI(f *testing.F) *fuzzedAPI {
	f.Helper()
	build := func(opts ...Option) (*Auth, http.Handler) {
		all := append([]Option{WithAutoMigrate(), WithLogger(discardingLogger()), emailAndUsername(), WithServiceKey("billing", serviceKeyOf("billing")), WithMountPath("/auth")}, opts...)
		a, err := NewWithStore(newTestMemory(), []byte(testKey), all...)
		if err != nil {
			f.Fatal(err)
		}
		a.hasher = newHasher(f, weakParams)
		if _, err = a.Register(context.Background(), Registration{Identifiers: map[string]string{"email": "nina@example.com"}, Password: goodPassword}); err != nil {
			f.Fatal(err)
		}
		return a, a.Handler()
	}
	plainAuth, plain := build()
	_, jar := build(WithRefreshCookie())
	cookieLogin, err := plainAuth.Login(context.Background(), Credentials{Login: "nina@example.com", Password: goodPassword, Kind: SessionCookie})
	if err != nil {
		f.Fatal(err)
	}
	tokenLogin, err := plainAuth.Login(context.Background(), Credentials{Login: "nina@example.com", Password: goodPassword, Kind: SessionToken})
	if err != nil {
		f.Fatal(err)
	}
	return &fuzzedAPI{
		plain: plain, jar: jar,
		cookie: plainAuth.cookie + "=" + cookieLogin.Secret, csrf: cookieLogin.CSRFToken,
		access: tokenLogin.Tokens.AccessToken, refresh: tokenLogin.Tokens.RefreshToken,
	}
}

func FuzzHandler(f *testing.F) {
	api := newFuzzedAPI(f)
	login := `{"login":"nina@example.com","password":"` + goodPassword + `"}`
	change := `{"current_password":"` + goodPassword + `","new_password":"another password to choose"}`
	for _, seed := range []struct {
		jar                                                            bool
		method, path, contentType, body, origin, authorization, cookie string
	}{
		{false, "POST", "/login", "application/json", login, appOrigin, "", ""},
		{false, "POST", "/token", "application/json", login, "", "", ""},
		{true, "POST", "/token", "application/json", login, appOrigin, "", ""},
		{false, "POST", "/token/refresh", "application/json", `{"refresh_token":"` + api.refresh + `"}`, "", "", ""},
		{true, "POST", "/token/refresh", "", "", appOrigin, "", "__Secure-limb_refresh=" + api.refresh},
		{false, "POST", "/token/introspect", "application/json", `{"token":"` + api.access + `"}`, "", "Bearer " + serviceKeyOf("billing"), ""},
		{false, "POST", "/logout", "", "", appOrigin, "Bearer " + api.access, ""},
		{false, "POST", "/logout/all", "application/json", `{"password":"x"}`, appOrigin, "", api.cookie},
		{false, "POST", "/password/change", "application/json", change, appOrigin, "Bearer " + api.access, ""},
		{false, "GET", "/sessions", "", "", "", "Bearer " + api.access, ""},
		{false, "GET", "/sessions/current", "", "", "", "", api.cookie},
		{false, "DELETE", "/sessions/someone", "application/json", `{"password":"x"}`, appOrigin, "Bearer " + api.access, ""},
		{false, "GET", "/.well-known/jwks.json", "", "", "", "", ""},
		{false, "OPTIONS", "/login", "", "", "", "", ""},
		{false, "GET", "/", "", "", "", "", ""},
		{false, "POST", "/login/", "application/json", "[]", "", "", ""},
		{false, "PROPFIND", "/sessions/a/b", "text/plain", "\x00", "null", "Digest realm", "a=b; c"},
	} {
		f.Add(seed.jar, seed.method, seed.path, seed.contentType, seed.body, seed.origin, seed.authorization, seed.cookie)
	}
	f.Fuzz(func(t *testing.T, jar bool, method, path, contentType, body, origin, authorization, cookie string) {
		if !strings.HasPrefix(path, "/") || len(body) > 80<<10 {
			return
		}
		r, err := http.NewRequestWithContext(context.Background(), method, "https://app.example.com/", io.NopCloser(strings.NewReader(body)))
		if err != nil {
			return
		}
		r.URL = &url.URL{Scheme: "https", Host: "app.example.com", Path: path}
		r.RemoteAddr = "192.0.2.1:1234"
		for name, value := range map[string]string{"Content-Type": contentType, "Origin": origin, "Authorization": authorization, "Cookie": cookie, "Accept-Language": body} {
			if value != "" {
				r.Header.Set(name, value)
			}
		}
		handler := api.plain
		if jar {
			handler = api.jar
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if rec.Code >= http.StatusInternalServerError {
			t.Fatalf("%s %q answered %d: %s", method, path, rec.Code, rec.Body.String())
		}
		cacheControl := rec.Header().Get("Cache-Control")
		publishedKeys := rec.Code == http.StatusOK && cacheControl == "public, max-age=300"
		if cacheControl != "no-store" && !publishedKeys {
			t.Fatalf("%s %q answered %d with Cache-Control %q", method, path, rec.Code, cacheControl)
		}
		if rec.Code < http.StatusBadRequest {
			return
		}
		var answer errorBody
		if err = json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
			t.Fatalf("%s %q answered %d with a body that is not an error: %q", method, path, rec.Code, rec.Body.String())
		}
		want, known := statusOfCode[answer.Error.Code]
		if !known || answer.Error.Message == "" || (rec.Code != want && rec.Code != http.StatusRequestEntityTooLarge) {
			t.Fatalf("%s %q answered %d with %+v", method, path, rec.Code, answer.Error)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Fatalf("Content-Type = %q", got)
		}
	})
}
