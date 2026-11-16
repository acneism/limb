package limb

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acneism/limb/store"
)

const (
	appOrigin    = "https://app.example.com"
	secretReason = "the database is on fire at 10.0.0.5"
)

type apiFixture struct {
	*sessionFixture
	handler http.Handler
}

func newAPIFixture(t *testing.T, opts ...Option) *apiFixture {
	t.Helper()
	f := newSessionFixture(t, opts...)
	return &apiFixture{sessionFixture: f, handler: f.a.Handler()}
}

type requestOption func(*http.Request)

func header(name, value string) requestOption {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

func sameOrigin() requestOption {
	return header("Sec-Fetch-Site", "same-origin")
}

func fromOrigin(origin string) requestOption {
	return header("Origin", origin)
}

func bearer(token string) requestOption {
	return header("Authorization", "Bearer "+token)
}

func asJSON() requestOption {
	return header("Content-Type", "application/json")
}

func withCookie(name, value string) requestOption {
	return func(r *http.Request) { r.Header.Add("Cookie", name+"="+value) }
}

func fromAddress(addr string) requestOption {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

func (f *apiFixture) sessionCookie(secret string) requestOption {
	return withCookie(f.a.cookie, secret)
}

func (f *apiFixture) signed(login Login) []requestOption {
	return []requestOption{f.sessionCookie(login.Secret), sameOrigin(), header(csrfHeader, login.CSRFToken)}
}

func bodyOf(t *testing.T, body any) *bytes.Reader {
	t.Helper()
	switch v := body.(type) {
	case nil:
		return bytes.NewReader(nil)
	case string:
		return bytes.NewReader([]byte(v))
	case []byte:
		return bytes.NewReader(v)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(raw)
}

func (f *apiFixture) send(t *testing.T, method, path string, body any, opts ...requestOption) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, appOrigin+path, bodyOf(t, body))
	r.Header.Set("User-Agent", testAgent)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, opt := range opts {
		opt(r)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, r)
	return rec
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("the body is not the JSON expected: %v\n%s", err, rec.Body.String())
	}
	return out
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	return decodeBody[map[string]any](t, rec)
}

func (f *apiFixture) expectError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d: %s", rec.Code, status, rec.Body.String())
	}
	got := decodeBody[errorBody](t, rec)
	if got.Error.Code != code || got.Error.Message == "" {
		t.Fatalf("error = %+v, want code %q with a message", got.Error, code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (f *apiFixture) loginRequest() map[string]string {
	return map[string]string{"login": "nina@example.com", "password": goodPassword}
}

func (f *apiFixture) signIn(t *testing.T) (Login, *httptest.ResponseRecorder) {
	t.Helper()
	rec := f.send(t, http.MethodPost, "/login", f.loginRequest(), sameOrigin())
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /login = %d: %s", rec.Code, rec.Body.String())
	}
	cookie := cookieNamed(rec, f.a.cookie)
	if cookie == nil {
		t.Fatal("POST /login set no session cookie")
	}
	body := decodeBody[cookieSessionBody](t, rec)
	return Login{
		Principal: Principal{UserID: UserID(body.UserID), SessionID: body.SessionID, SessionKind: SessionCookie},
		Secret:    cookie.Value,
		CSRFToken: body.CSRFToken,
		ExpiresAt: body.ExpiresAt,
	}, rec
}

func (f *apiFixture) signInWithTokens(t *testing.T) (tokenSessionBody, *httptest.ResponseRecorder) {
	t.Helper()
	rec := f.send(t, http.MethodPost, "/token", f.loginRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token = %d: %s", rec.Code, rec.Body.String())
	}
	return decodeBody[tokenSessionBody](t, rec), rec
}

func (f *apiFixture) restrict(t *testing.T) {
	t.Helper()
	f.change(t, func(u *store.User) { u.MustChangePassword = true })
}

func (f *apiFixture) bearerError(t *testing.T, token string) error {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, appOrigin+"/page", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	_, err := f.a.Authenticate(r)
	return err
}
