package limb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/acneism/limb/identifier"
)

var strictExtraName = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

func strictExtraValue(value string) bool {
	if len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
	})
}

func FuzzCheckExtra(f *testing.F) {
	for _, seed := range [][4]string{
		{"invite", "welcome-2026", "", ""},
		{"a.b_c-9", "", "x", "y"},
		{"Invite", "x", "", ""},
		{"", "x", "", ""},
		{"invite", "a\nb", "", ""},
		{"invite", "a\xffb", "", ""},
		{"invite", "a b", "", ""},
		{strings.Repeat("a", 65), "x", "", ""},
		{"invite", strings.Repeat("я", 513), "", ""},
		{"in vite", "x", "ключ", "значение"},
	} {
		f.Add(seed[0], seed[1], seed[2], seed[3])
	}
	f.Fuzz(func(t *testing.T, name1, value1, name2, value2 string) {
		extra := map[string]string{name1: value1, name2: value2}
		err := checkExtra(extra)
		allowed := true
		for name, value := range extra {
			allowed = allowed && strictExtraName.MatchString(name) && strictExtraValue(value)
		}
		var invalid *ValidationError
		switch {
		case err == nil && !allowed:
			t.Fatalf("checkExtra accepted %q", extra)
		case err != nil && allowed:
			t.Fatalf("checkExtra refused %q: %v", extra, err)
		case err != nil && (!errors.As(err, &invalid) || invalid.Field != "extra" || invalid.Reason == ""):
			t.Fatalf("checkExtra(%q) = %v, want a *ValidationError for extra", extra, err)
		}
	})
}

func FuzzCheckBaseURL(f *testing.F) {
	for _, seed := range []string{
		"", "https://app.example.com/reset", "http://localhost:3000/reset", "https://user@app.example.com/x",
		"https://app.example.com/x#y", "https://app.example.com/ x", "//app.example.com", "https:///x",
		"javascript:alert(1)", "https://app.example.com/\x00", "https://[::1]/x", "HTTPS://APP.EXAMPLE.COM",
		"https://app.example.com/a" + string(rune(0x2028)) + "b", "https://%zz",
	} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, address string, development bool) {
		if err := checkBaseURL("WithResetURL", address, development); err != nil || address == "" {
			return
		}
		u, err := url.Parse(address)
		switch {
		case err != nil, u.Host == "", u.User != nil, u.Fragment != "", u.RawFragment != "", strings.Contains(address, "#"):
			t.Fatalf("checkBaseURL accepted %q: %+v, %v", address, u, err)
		case len(address) > maxBaseURLLength, hasControl(address), strings.ContainsAny(address, " \t"):
			t.Fatalf("checkBaseURL accepted %q", address)
		case u.Scheme != "https" && (u.Scheme != "http" || !development):
			t.Fatalf("checkBaseURL accepted the scheme %q of %q", u.Scheme, address)
		}
	})
}

func FuzzRecoveryHandler(f *testing.F) {
	hook := func(_ context.Context, r Registration) error {
		switch r.Extra["invite"] {
		case "refuse":
			return &ValidationError{Field: "extra.invite", Reason: "refused"}
		case "fail":
			return errors.New("the hook failed")
		case "panic":
			panic("the hook panicked")
		}
		return nil
	}
	a, err := NewWithStore(newTestMemory(), []byte(testKey), WithAutoMigrate(), WithLogger(discardingLogger()),
		WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username()),
		WithSender(senderFunc(func(context.Context, Message) error { return nil })), WithSignup(), WithHooks(Hooks{BeforeRegister: hook}),
		WithVerifyURL("https://app.example.com/verify"), WithResetURL("https://app.example.com/reset"), manyRequests())
	if err != nil {
		f.Fatal(err)
	}
	a.hasher = newHasher(f, weakParams)
	f.Cleanup(func() { _ = a.Shutdown(context.Background()) })
	handler := a.Handler()
	paths := []string{"/register", "/verify", "/verify/confirm", "/password/reset", "/password/reset/confirm"}
	succeeded := map[string]int{
		"/register": http.StatusAccepted, "/verify": http.StatusAccepted, "/verify/confirm": http.StatusNoContent,
		"/password/reset": http.StatusAccepted, "/password/reset/confirm": http.StatusNoContent,
	}
	for _, seed := range []struct {
		route                 uint8
		body, contentType, tr string
	}{
		{0, `{"identifiers":{"email":"olga@example.com","username":"olga_o"},"password":"` + goodPassword + `"}`, "application/json", "ru"},
		{0, `{"identifiers":{"email":"nina@example.com"},"password":"` + goodPassword + `","extra":{"invite":"refuse"}}`, "application/json", ""},
		{0, `{"identifiers":{"email":"olga@example.com"},"password":"` + goodPassword + `","extra":{"invite":"fail"}}`, "application/json", ""},
		{0, `{"identifiers":{"email":"olga@example.com"},"password":"` + goodPassword + `","extra":{"invite":"panic"}}`, "application/json", ""},
		{0, `{"identifiers":{"email":"olga@example.com"},"password":"` + goodPassword + `","verified":["email"]}`, "application/json", ""},
		{1, `{"login":"nina@example.com"}`, "application/json", "en"},
		{2, `{"token":"` + strings.Repeat("A", 43) + `"}`, "application/json", ""},
		{2, `{"login":"nina_n","code":"123456"}`, "application/json", ""},
		{3, `{"login":"nobody@example.com"}`, "application/json", ""},
		{4, `{"channel":"nina@example.com","code":"123 456","password":"` + goodPassword + `"}`, "application/json", ""},
		{4, `{"token":"x","code":"1"}`, "application/json", ""},
		{1, `null`, "application/json", ""},
		{3, ``, "", ""},
	} {
		f.Add(seed.route, seed.body, seed.contentType, seed.tr)
	}
	f.Fuzz(func(t *testing.T, route uint8, body, contentType, language string) {
		if len(body) > 80<<10 {
			return
		}
		path := paths[int(route)%len(paths)]
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://app.example.com"+path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		if language != "" {
			r.Header.Set("Accept-Language", language)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if len(rec.Result().Cookies()) != 0 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("POST %s answered with cookies %v and Cache-Control %q", path, rec.Result().Cookies(), rec.Header().Get("Cache-Control"))
		}
		if rec.Code < http.StatusBadRequest {
			if rec.Code != succeeded[path] {
				t.Fatalf("POST %s answered %d, want %d", path, rec.Code, succeeded[path])
			}
			return
		}
		var answer errorBody
		if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
			t.Fatalf("POST %s answered %d with a body that is not an error: %q", path, rec.Code, rec.Body.String())
		}
		want, known := statusOfCode[answer.Error.Code]
		if !known || answer.Error.Message == "" || (rec.Code != want && rec.Code != http.StatusRequestEntityTooLarge) {
			t.Fatalf("POST %s answered %d with %+v", path, rec.Code, answer.Error)
		}
		if rec.Code >= http.StatusInternalServerError && answer.Error.Code != codeBusy {
			t.Fatalf("POST %s answered %d: %s", path, rec.Code, rec.Body.String())
		}
		if len(body) >= 12 && strings.Contains(rec.Body.String(), body) {
			t.Fatalf("POST %s echoed the request: %s", path, rec.Body.String())
		}
	})
}
