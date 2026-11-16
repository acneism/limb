package limb

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestNegotiateLanguage(t *testing.T) {
	cases := map[string]string{
		"":                                "en",
		"en":                              "en",
		"ru":                              "ru",
		"ru-RU":                           "ru",
		"RU":                              "ru",
		"en-GB":                           "en",
		"ru-RU,ru;q=0.9,en;q=0.8":         "ru",
		"en-GB,ru;q=0.5":                  "en",
		"en;q=0.5,ru;q=0.8":               "ru",
		"ru;q=0.5,en;q=0.5":               "ru",
		"en;q=0.5,ru;q=0.5":               "en",
		"fr,de":                           "en",
		"fr, ru;q=0.1":                    "ru",
		"*":                               "en",
		"*;q=0.5, ru;q=0.4":               "ru",
		"ru;q=0":                          "en",
		"ru;q=0, en":                      "en",
		"ru;q=abc":                        "en",
		"ru;q=1.5":                        "en",
		"ru;q=-1":                         "en",
		"ru ; q = 0.7 , en;q=0.6":         "ru",
		"ru;Q=0.3,en;q=0.2":               "ru",
		"ru;level=1;q=0.9,en;q=0.8":       "ru",
		";q=1":                            "en",
		",,,":                             "en",
		"ru;;;":                           "ru",
		"русский":                         "en",
		strings.Repeat("fr,", 40) + "ru":  "en",
		strings.Repeat("a", 5000) + ",ru": "en",
	}
	for header, want := range cases {
		if got := negotiateLanguage(header); got != want {
			t.Errorf("negotiateLanguage(%.40q) = %q, want %q", header, got, want)
		}
	}
}

func FuzzNegotiateLanguage(f *testing.F) {
	for _, seed := range []string{"", "ru", "en;q=0.5,ru;q=0.8", "*;q=0", ";;;", "ru;q=", "ru;q=0.5;q=0.9", strings.Repeat(",ru", 100)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		if got := negotiateLanguage(header); got != "en" && got != "ru" {
			t.Fatalf("negotiateLanguage(%q) = %q", header, got)
		}
	})
}

func TestEveryCodeHasAStatusAndTwoMessages(t *testing.T) {
	want := map[string]int{
		codeInvalidRequest: 400, codeInvalidCredentials: 401, codeUserBlocked: 403, codeRateLimited: 429,
		codePasswordChangeRequired: 403, codeUnauthenticated: 401, codeCSRFFailed: 403, codePolicyViolation: 422,
		codeNotFound: 404, codeMethodNotAllowed: 405, codeUnsupportedMediaType: 415, codeInternal: 500,
	}
	if len(statusOfCode) != len(want) {
		t.Fatalf("statuses = %v", statusOfCode)
	}
	for code, status := range want {
		if statusOfCode[code] != status {
			t.Errorf("%s has the status %d, want %d", code, statusOfCode[code], status)
		}
		for language, texts := range messages {
			if strings.TrimSpace(texts[code]) == "" {
				t.Errorf("%s has no message in %s", code, language)
			}
		}
	}
	for language, texts := range messages {
		if len(texts) != len(want)+1 || texts[messageRequestTooLarge] == "" {
			t.Errorf("%s has %d messages", language, len(texts))
		}
	}
	for code := range messages["en"] {
		if _, ok := messages["ru"][code]; !ok {
			t.Errorf("%s is not translated", code)
		}
	}
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) (errorFields, map[string]any) {
	t.Helper()
	var generic map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &generic); err != nil {
		t.Fatalf("the body %q is not JSON: %v", rec.Body.String(), err)
	}
	var typed errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &typed); err != nil {
		t.Fatal(err)
	}
	return typed.Error, generic
}

func TestWriteErrorAnswersInTheLanguageOfTheClient(t *testing.T) {
	for _, tc := range []struct {
		language string
		want     string
	}{{"", messages["en"][codeUnauthenticated]}, {"ru", messages["ru"][codeUnauthenticated]}, {"de, ru;q=0.4", messages["ru"][codeUnauthenticated]}} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		if tc.language != "" {
			r.Header.Set("Accept-Language", tc.language)
		}
		writeError(rec, r, newAPIError(codeUnauthenticated))
		fields, generic := decodeError(t, rec)
		if rec.Code != 401 || fields.Code != codeUnauthenticated || fields.Message != tc.want {
			t.Fatalf("%q: %d %+v, want 401 and %q", tc.language, rec.Code, fields, tc.want)
		}
		if len(generic) != 1 || len(generic["error"].(map[string]any)) != 2 { //nolint:forcetypeassert
			t.Fatalf("the body must be exactly {\"error\":{\"code\",\"message\"}}: %s", rec.Body.String())
		}
	}
}

func TestEveryAnswerIsMarkedAsNotToBeCachedOrSniffed(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), newAPIError(codeNotFound))
	h := rec.Header()
	if h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("headers = %v", h)
	}
	if h.Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers = %v", h)
	}
}

func TestAPolicyErrorCarriesItsRulesAndAnotherHeaderCanBeAdded(t *testing.T) {
	rec := httptest.NewRecorder()
	e := newAPIError(codePolicyViolation)
	e.rules = []string{"min_length", "common_password"}
	e.with("X-Test", "1").with("Allow", "GET, POST")
	writeError(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil), e)
	fields, _ := decodeError(t, rec)
	if rec.Code != 422 || len(fields.Rules) != 2 || fields.Rules[0] != "min_length" || rec.Header().Get("X-Test") != "1" || rec.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("%d %+v %v", rec.Code, fields, rec.Header())
	}
	plain := httptest.NewRecorder()
	writeError(plain, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil), newAPIError(codeNotFound))
	if strings.Contains(plain.Body.String(), "rules") {
		t.Fatalf("an error without rules must not have the field: %s", plain.Body.String())
	}
}

func TestAMessageWithoutATranslationFallsBackToEnglish(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.Header.Set("Accept-Language", "ru")
	e := newAPIError(codeNotFound)
	e.message = "only_in_english"
	messages["en"]["only_in_english"] = "Only here."
	defer delete(messages["en"], "only_in_english")
	writeError(rec, r, e)
	if fields, _ := decodeError(t, rec); fields.Message != "Only here." {
		t.Fatalf("%+v", fields)
	}
}

type loginBody struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func readBody(t *testing.T, body io.Reader, contentType string, required bool) (loginBody, *apiError) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", body)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	var into loginBody
	rec := httptest.NewRecorder()
	return into, readJSON(rec, r, &into, required)
}

func TestReadJSON(t *testing.T) {
	just := func(size int) string {
		padding := size - len(`{"login":""}`)
		return `{"login":"` + strings.Repeat("a", padding) + `"}`
	}
	cases := []struct {
		name        string
		body        string
		contentType string
		required    bool
		wantCode    string
		wantStatus  int
	}{
		{name: "a good body", body: `{"login":"a","password":"b"}`, contentType: "application/json", required: true},
		{name: "with a charset", body: `{"login":"a"}`, contentType: "application/json; charset=utf-8", required: true},
		{name: "in capitals", body: `{"login":"a"}`, contentType: "APPLICATION/JSON", required: true},
		{name: "with spaces around", body: " \n{\"login\":\"a\"}\n ", contentType: "application/json", required: true},
		{name: "an empty body that is optional", body: "", required: false},
		{name: "an empty body that is optional with the wrong type", body: "", contentType: "text/plain", required: false},
		{name: "a blank body that is optional", body: " \n ", required: false},
		{name: "an empty body that is required", body: "", contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "no content type", body: `{"login":"a"}`, required: true, wantCode: codeUnsupportedMediaType, wantStatus: 415},
		{name: "a form", body: `{"login":"a"}`, contentType: "application/x-www-form-urlencoded", required: true, wantCode: codeUnsupportedMediaType, wantStatus: 415},
		{name: "plain text", body: `{"login":"a"}`, contentType: "text/plain", required: true, wantCode: codeUnsupportedMediaType, wantStatus: 415},
		{name: "a broken content type", body: `{"login":"a"}`, contentType: "application/json;;;=", required: true, wantCode: codeUnsupportedMediaType, wantStatus: 415},
		{name: "a similar type", body: `{"login":"a"}`, contentType: "application/jsonp", required: true, wantCode: codeUnsupportedMediaType, wantStatus: 415},
		{name: "an unknown field", body: `{"login":"a","admin":true}`, contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "a field twice with another name", body: `{"login":"a","LOGIN":"b","x":1}`, contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "broken JSON", body: `{"login":`, contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "not an object", body: `["a"]`, contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "a string", body: `"a"`, contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "null", body: `null`, contentType: "application/json", required: true},
		{name: "a wrong type of a value", body: `{"login":1}`, contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "two objects", body: `{"login":"a"}{"login":"b"}`, contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "an object and junk", body: `{"login":"a"} x`, contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "an object and a comma", body: `{"login":"a"},`, contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 400},
		{name: "the largest body", body: just(maxBodyBytes), contentType: "application/json", required: true},
		{name: "one byte too many", body: just(maxBodyBytes + 1), contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 413},
		{name: "a huge body", body: just(maxBodyBytes * 20), contentType: "application/json", required: true, wantCode: codeInvalidRequest, wantStatus: 413},
		{name: "a huge body with the wrong type", body: just(maxBodyBytes * 20), contentType: "text/plain", required: true, wantCode: codeInvalidRequest, wantStatus: 413},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readBody(t, strings.NewReader(tc.body), tc.contentType, tc.required)
			switch {
			case tc.wantCode == "" && err != nil:
				t.Fatalf("readJSON = %+v, want success", err)
			case tc.wantCode != "" && (err == nil || err.code != tc.wantCode || err.status != tc.wantStatus):
				t.Fatalf("readJSON = %+v, want %s with the status %d", err, tc.wantCode, tc.wantStatus)
			}
		})
	}
}

func TestReadJSONFillsTheFieldsAndHandlesAMissingBody(t *testing.T) {
	got, err := readBody(t, strings.NewReader(`{"login":"nina","password":"secret value"}`), "application/json", true)
	if err != nil || got != (loginBody{Login: "nina", Password: "secret value"}) {
		t.Fatalf("readJSON = %+v, %v", got, err)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	r.Body = nil
	var into loginBody
	if e := readJSON(httptest.NewRecorder(), r, &into, false); e != nil {
		t.Fatalf("a request without a body = %+v, want success when the body is optional", e)
	}
	if e := readJSON(httptest.NewRecorder(), r, &into, true); e == nil || e.code != codeInvalidRequest {
		t.Fatalf("a request without a body = %+v, want invalid_request when it is required", e)
	}
}

func TestReadJSONSurvivesABrokenConnection(t *testing.T) {
	_, err := readBody(t, iotest.ErrReader(errors.New("connection reset")), "application/json", true)
	if err == nil || err.code != codeInvalidRequest || err.status != 400 {
		t.Fatalf("readJSON = %+v, want invalid_request", err)
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for in, want := range map[time.Duration]string{
		0: "1", time.Millisecond: "1", time.Second: "1", 1500 * time.Millisecond: "2", 15 * time.Minute: "900", 59*time.Second + time.Nanosecond: "60",
	} {
		if got := retryAfterSeconds(in); got != want {
			t.Errorf("retryAfterSeconds(%v) = %q, want %q", in, got, want)
		}
	}
}
