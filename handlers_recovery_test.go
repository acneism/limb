package limb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acneism/limb/identifier"
)

func newRecoveryAPI(t *testing.T, opts ...Option) (*recoveryFixture, *apiFixture) {
	t.Helper()
	f := newRecoveryFixture(t, append([]Option{WithSignup(), manyRequests()}, opts...)...)
	return f, &apiFixture{handler: f.a.Handler()}
}

func registration(email, nick string) map[string]any {
	return map[string]any{
		"identifiers": map[string]string{"email": email, "username": nick},
		"password":    goodPassword,
	}
}

func routeExists(t *testing.T, h http.Handler, path string) bool {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, appOrigin+path, nil))
	return rec.Code == http.StatusMethodNotAllowed && rec.Header().Get("Allow") == http.MethodPost
}

func TestTheRoutesOfRecoveryExistOnlyWhereTheServiceCanUseThem(t *testing.T) {
	sender := WithSender(&recordingSender{})
	cases := []struct {
		name     string
		auth     *Auth
		register bool
		recovery bool
	}{
		{"a service that sends nothing", newTestAuth(t, emailAndUsername()), false, false},
		{"a service that sends", newTestAuth(t, emailAndUsername(), sender), false, true},
		{"a service with signup", newTestAuth(t, emailAndUsername(), sender, WithSignup()), true, true},
		{"signup without a sender", newTestAuth(t, emailAndUsername(), WithSignup(), WithoutVerificationRequired()), true, false},
		{"a service without a channel", newTestAuth(t, WithIdentifiers(identifier.Username(identifier.Required())), sender, WithSignup()), true, false},
		{"the routes turned off", newTestAuth(t, emailAndUsername(), sender, WithSignup(),
			WithoutEndpoints(EndpointRegister, EndpointVerify, EndpointPasswordReset)), false, false},
	}
	for _, c := range cases {
		h := c.auth.Handler()
		if got := routeExists(t, h, "/register"); got != c.register {
			t.Errorf("%s: POST /register exists = %v, want %v", c.name, got, c.register)
		}
		for _, path := range []string{"/verify", "/verify/confirm", "/password/reset", "/password/reset/confirm"} {
			if got := routeExists(t, h, path); got != c.recovery {
				t.Errorf("%s: POST %s exists = %v, want %v", c.name, path, got, c.recovery)
			}
		}
	}
	_, api := newRecoveryAPI(t)
	for _, path := range []string{"/register", "/verify", "/verify/confirm", "/password/reset", "/password/reset/confirm"} {
		rec := api.send(t, http.MethodGet, path, nil)
		api.expectError(t, rec, http.StatusMethodNotAllowed, "method_not_allowed")
		if allow := rec.Header().Get("Allow"); allow != http.MethodPost {
			t.Errorf("GET %s: Allow = %q", path, allow)
		}
	}
}

func TestAVisitorRegistersConfirmsTheAddressAndSignsIn(t *testing.T) {
	f, api := newRecoveryAPI(t)
	rec := api.send(t, http.MethodPost, "/register", registration("Olga@Example.com", "olga_o"), header("Accept-Language", "ru-RU,ru;q=0.9"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /register = %d: %s", rec.Code, rec.Body.String())
	}
	if got := decodeMap(t, rec); len(got) != 1 || got["verification_required"] != true {
		t.Fatalf("body = %v, want only verification_required", got)
	}
	m := f.messages(t, 1)[0]
	if m.Kind != MessageVerification || m.To != "olga@example.com" || m.Language != "ru" || m.Link == "" {
		t.Fatalf("message = %+v", m)
	}
	login := map[string]string{"login": "olga_o", "password": goodPassword}
	api.expectError(t, api.send(t, http.MethodPost, "/login", login, sameOrigin()), http.StatusForbidden, "verification_required")
	api.expectError(t, api.send(t, http.MethodPost, "/token", login), http.StatusForbidden, "verification_required")
	refused := api.send(t, http.MethodPost, "/login", login, sameOrigin(), header("Accept-Language", "ru"))
	if got := decodeBody[errorBody](t, refused).Error.Message; !strings.Contains(got, "подтвердите") {
		t.Fatalf("message = %q, want it in Russian", got)
	}
	rec = api.send(t, http.MethodPost, "/verify/confirm", map[string]string{"token": tokenOf(m.Link)})
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("POST /verify/confirm = %d: %s", rec.Code, rec.Body.String())
	}
	if rec = api.send(t, http.MethodPost, "/login", login, sameOrigin()); rec.Code != http.StatusOK {
		t.Fatalf("POST /login after the confirmation = %d: %s", rec.Code, rec.Body.String())
	}
	if rec = api.send(t, http.MethodPost, "/verify/confirm", map[string]string{"token": tokenOf(m.Link)}); rec.Code != http.StatusBadRequest {
		t.Fatalf("the link a second time = %d", rec.Code)
	}
}

func TestARegistrationThatUsesATakenAddressIsAnsweredLikeAnyOther(t *testing.T) {
	f, api := newRecoveryAPI(t)
	free := api.send(t, http.MethodPost, "/register", registration("olga@example.com", "olga_o"))
	f.messages(t, 1)
	f.sender.clear()
	taken := api.send(t, http.MethodPost, "/register", registration("nina@example.com", "other_o"))
	if free.Code != taken.Code || free.Body.String() != taken.Body.String() || free.Header().Get("Content-Type") != taken.Header().Get("Content-Type") {
		t.Fatalf("free: %d %q, taken: %d %q", free.Code, free.Body.String(), taken.Code, taken.Body.String())
	}
	if m := f.ofKind(t, MessageSignupAttempt, 1)[0]; m.To != "nina@example.com" {
		t.Fatalf("notice = %+v", m)
	}
	if f.exists(t, "username", "other_o") {
		t.Fatal("the registration with a taken address created a user")
	}
}

func TestARegistrationThatIsNotValidSaysWhichValueIsWrong(t *testing.T) {
	f, api := newRecoveryAPI(t)
	cases := []struct {
		name   string
		body   map[string]any
		status int
		code   string
		field  string
	}{
		{"a taken nickname", registration("olga@example.com", "NINA_N"), 422, "validation_failed", "username"},
		{"a bad address", registration("olga", "olga_o"), 422, "validation_failed", "email"},
		{"no address", map[string]any{"identifiers": map[string]string{"username": "olga_o"}, "password": goodPassword}, 422, "validation_failed", "email"},
		{"an unknown type", map[string]any{"identifiers": map[string]string{"email": "olga@example.com", "fax": "1"}, "password": goodPassword}, 422, "validation_failed", "fax"},
		{"a bad extra", map[string]any{"identifiers": map[string]string{"email": "olga@example.com"}, "password": goodPassword, "extra": map[string]string{"Bad Name": "x"}}, 422, "validation_failed", "extra"},
		{"a weak password", map[string]any{"identifiers": map[string]string{"email": "olga@example.com"}, "password": "short"}, 422, "policy_violation", ""},
		{"no password", map[string]any{"identifiers": map[string]string{"email": "olga@example.com"}}, 422, "policy_violation", ""},
	}
	for _, c := range cases {
		rec := api.send(t, http.MethodPost, "/register", c.body)
		api.expectError(t, rec, c.status, c.code)
		got := decodeBody[errorBody](t, rec).Error
		if got.Field != c.field || (c.field != "" && got.Reason == "") {
			t.Errorf("%s: field = %q, reason = %q", c.name, got.Field, got.Reason)
		}
		if c.code == "policy_violation" && len(got.Rules) == 0 {
			t.Errorf("%s: no rules", c.name)
		}
	}
	f.wantNothingCreated(t, "email", "olga@example.com")
	f.noMessages(t)
}

func TestWhatTheHookSaysReachesTheVisitor(t *testing.T) {
	f, api := newRecoveryAPI(t)
	body := map[string]any{
		"identifiers": map[string]string{"email": "olga@example.com"}, "password": goodPassword, "extra": map[string]string{"invite": "welcome"},
	}
	f.a.hooks.BeforeRegister = func(context.Context, Registration) error {
		return &ValidationError{Field: "extra.invite", Reason: "the invitation has expired"}
	}
	rec := api.send(t, http.MethodPost, "/register", body)
	api.expectError(t, rec, http.StatusUnprocessableEntity, "validation_failed")
	if got := decodeBody[errorBody](t, rec).Error; got.Field != "extra.invite" || got.Reason != "the invitation has expired" {
		t.Fatalf("error = %+v", got)
	}
	f.a.hooks.BeforeRegister = func(context.Context, Registration) error { return errors.New("the list of invitations is down") }
	rec = api.send(t, http.MethodPost, "/register", body)
	api.expectError(t, rec, http.StatusForbidden, "registration_refused")
	if strings.Contains(rec.Body.String(), "invitations") {
		t.Fatalf("the cause of the refusal reached the visitor: %s", rec.Body.String())
	}
	f.a.hooks.BeforeRegister = func(context.Context, Registration) error { panic("no") }
	api.expectError(t, api.send(t, http.MethodPost, "/register", body), http.StatusForbidden, "registration_refused")
	f.a.hooks.BeforeRegister = func(_ context.Context, r Registration) error {
		if r.Extra["invite"] != "welcome" {
			return errors.New("no invitation")
		}
		return nil
	}
	if rec = api.send(t, http.MethodPost, "/register", body); rec.Code != http.StatusAccepted {
		t.Fatalf("POST /register with the invitation = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestARequestToRegisterCannotConfirmAnAddress(t *testing.T) {
	f, api := newRecoveryAPI(t)
	for _, name := range []string{"verified", "Verified", "VERIFIED"} {
		body := registration("olga@example.com", "olga_o")
		body[name] = []string{"email"}
		api.expectError(t, api.send(t, http.MethodPost, "/register", body), http.StatusBadRequest, "invalid_request")
	}
	f.wantNothingCreated(t, "email", "olga@example.com")
	raw := `{"identifiers":{"email":"olga@example.com","username":"olga_o"},"password":"` + goodPassword + `","verified":["email"]}`
	api.expectError(t, api.send(t, http.MethodPost, "/register", raw), http.StatusBadRequest, "invalid_request")
	if rec := api.send(t, http.MethodPost, "/register", registration("olga@example.com", "olga_o")); rec.Code != http.StatusAccepted {
		t.Fatal(rec.Body.String())
	}
	if f.identifierOf(t, "email").VerifiedAt.IsZero() == false {
		t.Fatal("the address is confirmed without a message")
	}
}

func TestTheBodiesOfRecoveryAreCheckedLikeThoseOfSignIn(t *testing.T) {
	_, api := newRecoveryAPI(t)
	for _, path := range []string{"/register", "/verify", "/verify/confirm", "/password/reset", "/password/reset/confirm"} {
		api.expectError(t, api.send(t, http.MethodPost, path, nil), http.StatusBadRequest, "invalid_request")
		api.expectError(t, api.send(t, http.MethodPost, path, `{"login":"x"}`, header("Content-Type", "text/plain")), http.StatusUnsupportedMediaType, "unsupported_media_type")
		api.expectError(t, api.send(t, http.MethodPost, path, `{"nothing":"x"}`), http.StatusBadRequest, "invalid_request")
		api.expectError(t, api.send(t, http.MethodPost, path, `{"login":"x"} {}`), http.StatusBadRequest, "invalid_request")
		api.expectError(t, api.send(t, http.MethodPost, path, `{"login":`), http.StatusBadRequest, "invalid_request")
		big := `{"login":"` + strings.Repeat("a", maxBodyBytes) + `"}`
		api.expectError(t, api.send(t, http.MethodPost, path, big), http.StatusRequestEntityTooLarge, "invalid_request")
	}
}

func TestARegistrationIsLimitedPerAddressAndPerClient(t *testing.T) {
	f := newRecoveryFixture(t, WithSignup())
	api := &apiFixture{handler: f.a.Handler()}
	for i := range 3 {
		rec := api.send(t, http.MethodPost, "/register", registration("olga@example.com", fmt.Sprintf("nick_%d", i)), fromAddress("198.51.100.1:1"))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("registration %d = %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := api.send(t, http.MethodPost, "/register", registration("olga@example.com", "nd_nick"), fromAddress("198.51.100.2:1"))
	api.expectError(t, rec, http.StatusTooManyRequests, "rate_limited")
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
}

func TestAVisitorAsksForAMessageThatConfirmsAnAddress(t *testing.T) {
	f, api := newRecoveryAPI(t)
	rec := api.send(t, http.MethodPost, "/verify", map[string]string{"login": "nina_n"}, header("Accept-Language", "ru"))
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("POST /verify = %d: %q", rec.Code, rec.Body.String())
	}
	if m := f.messages(t, 1)[0]; m.Kind != MessageVerification || m.Language != "ru" {
		t.Fatalf("message = %+v", m)
	}
	unknown := api.send(t, http.MethodPost, "/verify", map[string]string{"login": "nobody@example.com"})
	if unknown.Code != rec.Code || unknown.Body.String() != rec.Body.String() {
		t.Fatalf("an unknown login = %d %q, a known one = %d %q", unknown.Code, unknown.Body.String(), rec.Code, rec.Body.String())
	}
}

func TestAVisitorConfirmsAnAddressWithTheCodeByLoginOrByChannel(t *testing.T) {
	for name, body := range map[string]map[string]string{
		"by login":   {"login": "nina_n"},
		"by channel": {"channel": "NINA@example.com"},
	} {
		f, api := newRecoveryAPI(t)
		m := f.sendVerification(t)
		body["code"] = m.Code[:3] + " " + m.Code[3:]
		if rec := api.send(t, http.MethodPost, "/verify/confirm", body); rec.Code != http.StatusNoContent {
			t.Fatalf("%s: POST /verify/confirm = %d: %s", name, rec.Code, rec.Body.String())
		}
		if f.identifierOf(t, "email").VerifiedAt.IsZero() {
			t.Fatalf("%s: the address is not confirmed", name)
		}
	}
}

func TestAConfirmationNeedsOneKindOfProof(t *testing.T) {
	_, api := newRecoveryAPI(t)
	for _, path := range []string{"/verify/confirm", "/password/reset/confirm"} {
		with := func(fields map[string]string) map[string]string {
			if path == "/password/reset/confirm" {
				fields["password"] = goodPassword
			}
			return fields
		}
		for name, body := range map[string]map[string]string{
			"a token and a code":     with(map[string]string{"token": "abc", "code": "123456"}),
			"a login without a code": with(map[string]string{"login": "nina_n"}),
			"a code alone":           with(map[string]string{"code": "123456"}),
		} {
			t.Run(path+" "+name, func(t *testing.T) {
				api.expectError(t, api.send(t, http.MethodPost, path, body), http.StatusUnprocessableEntity, "validation_failed")
			})
		}
		rec := api.send(t, http.MethodPost, path, with(map[string]string{"token": strings.Repeat("A", 43)}))
		api.expectError(t, rec, http.StatusBadRequest, "invalid_secret")
		rec = api.send(t, http.MethodPost, path, with(map[string]string{"login": "nina_n", "code": "000000"}))
		api.expectError(t, rec, http.StatusBadRequest, "invalid_secret")
	}
}

func TestAVisitorResetsThePasswordWithTheLinkOrTheCode(t *testing.T) {
	for _, proof := range []string{"link", "code"} {
		f, api := newRecoveryAPI(t)
		f.verify(t, "email", "nina@example.com")
		old, err := f.signIn(t, "nina_n", goodPassword)
		if err != nil {
			t.Fatal(err)
		}
		rec := api.send(t, http.MethodPost, "/password/reset", map[string]string{"login": "nina@example.com"})
		if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
			t.Fatalf("POST /password/reset = %d: %q", rec.Code, rec.Body.String())
		}
		m := f.ofKind(t, MessagePasswordReset, 1)[0]
		body := map[string]string{"password": "short"}
		if proof == "link" {
			body["token"] = tokenOf(m.Link)
		} else {
			body["login"], body["code"] = "nina_n", m.Code
		}
		weak := api.send(t, http.MethodPost, "/password/reset/confirm", body)
		api.expectError(t, weak, http.StatusUnprocessableEntity, "policy_violation")
		body["password"] = resetPassword
		rec = api.send(t, http.MethodPost, "/password/reset/confirm", body, header("Accept-Language", "ru"))
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Fatalf("%s: POST /password/reset/confirm = %d: %s", proof, rec.Code, rec.Body.String())
		}
		api.expectError(t, api.send(t, http.MethodPost, "/password/reset/confirm", body), http.StatusBadRequest, "invalid_secret")
		if f.sessionAlive(t, old) {
			t.Fatalf("%s: the session of before the reset survived it", proof)
		}
		if _, err = f.signIn(t, "nina_n", resetPassword); err != nil {
			t.Fatalf("%s: the new password does not work: %v", proof, err)
		}
		if notice := f.ofKind(t, MessagePasswordChanged, 1)[0]; notice.Language != "ru" {
			t.Fatalf("%s: notice = %+v, want the language of the request", proof, notice)
		}
	}
}

func TestAResetForALoginThatIsNotThereIsAnsweredAlike(t *testing.T) {
	f, api := newRecoveryAPI(t)
	f.verify(t, "email", "nina@example.com")
	known := api.send(t, http.MethodPost, "/password/reset", map[string]string{"login": "nina_n"})
	unknown := api.send(t, http.MethodPost, "/password/reset", map[string]string{"login": "nobody_n"})
	if known.Code != unknown.Code || known.Body.String() != unknown.Body.String() {
		t.Fatalf("known: %d %q, unknown: %d %q", known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
	}
	odd := api.send(t, http.MethodPost, "/password/reset", map[string]string{"login": "  "})
	api.expectError(t, odd, http.StatusUnprocessableEntity, "validation_failed")
}

func TestWrongSecretsOverHTTPLockTheClientOut(t *testing.T) {
	for _, path := range []string{"/verify/confirm", "/password/reset/confirm"} {
		f := newRecoveryFixture(t, WithSignup(), WithRecoveryLimits(RecoveryLimits{IPFailures: Limit{Attempts: 2}}))
		api := &apiFixture{handler: f.a.Handler()}
		body := map[string]string{"token": strings.Repeat("A", 43)}
		if path == "/password/reset/confirm" {
			body["password"] = goodPassword
		}
		for range 2 {
			api.expectError(t, api.send(t, http.MethodPost, path, body, fromAddress("198.51.100.1:1000")), http.StatusBadRequest, "invalid_secret")
		}
		rec := api.send(t, http.MethodPost, path, body, fromAddress("198.51.100.1:2000"))
		api.expectError(t, rec, http.StatusTooManyRequests, "rate_limited")
		if rec.Header().Get("Retry-After") == "" {
			t.Fatalf("POST %s: no Retry-After", path)
		}
		api.expectError(t, api.send(t, http.MethodPost, path, body, fromAddress("198.51.100.9:1000")), http.StatusBadRequest, "invalid_secret")
	}
}

func TestAFullQueueAnswers503ForEveryLogin(t *testing.T) {
	f, api := newRecoveryAPI(t, WithSending(SendingOptions{Workers: 1, Queue: 1}))
	release := f.block(t)
	if rec := api.send(t, http.MethodPost, "/password/reset", map[string]string{"login": "nina_n"}); rec.Code != http.StatusAccepted {
		t.Fatalf("the first request = %d", rec.Code)
	}
	var bodies []string
	for _, login := range []string{"nina_n", "nobody_n"} {
		rec := api.send(t, http.MethodPost, "/password/reset", map[string]string{"login": login})
		api.expectError(t, rec, http.StatusServiceUnavailable, "busy")
		if rec.Header().Get("Retry-After") != busyRetryAfter {
			t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
		}
		bodies = append(bodies, rec.Body.String())
	}
	if bodies[0] != bodies[1] {
		t.Fatalf("the answers differ: %v", bodies)
	}
	api.expectError(t, api.send(t, http.MethodPost, "/verify", map[string]string{"login": "nina_n"}), http.StatusServiceUnavailable, "busy")
	release()
}

func TestOnlyTheErrorsOfValuesCarryAFieldAndAReason(t *testing.T) {
	_, api := newRecoveryAPI(t)
	rec := api.send(t, http.MethodPost, "/verify/confirm", map[string]string{"token": strings.Repeat("A", 43)})
	if strings.Contains(rec.Body.String(), "field") || strings.Contains(rec.Body.String(), "reason") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	rec = api.send(t, http.MethodPost, "/register", registration("olga", "olga_o"))
	if !strings.Contains(rec.Body.String(), `"field":"email"`) || !strings.Contains(rec.Body.String(), `"reason":`) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestTheRoutesOfRecoveryNeedNoSessionAndSetNoCookie(t *testing.T) {
	f, api := newRecoveryAPI(t)
	f.verify(t, "email", "nina@example.com")
	for _, c := range []struct {
		path string
		body any
	}{
		{"/register", registration("olga@example.com", "olga_o")},
		{"/verify", map[string]string{"login": "nina_n"}},
		{"/password/reset", map[string]string{"login": "nina_n"}},
	} {
		rec := api.send(t, http.MethodPost, c.path, c.body)
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("POST %s set a cookie", c.path)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("POST %s: headers = %v", c.path, rec.Header())
		}
	}
}

func TestAServiceWithoutADeliveryChannelHasNoRecoveryRoutes(t *testing.T) {
	a := newTestAuth(t, WithIdentifiers(identifier.Username(identifier.Required())), WithSender(&recordingSender{}), WithSignup())
	api := &apiFixture{handler: a.Handler()}
	api.expectError(t, api.send(t, http.MethodPost, "/password/reset", map[string]string{"login": "x"}), http.StatusNotFound, "not_found")
	if rec := api.send(t, http.MethodPost, "/register", map[string]any{"identifiers": map[string]string{"username": "olga_o"}, "password": goodPassword}); rec.Code != http.StatusAccepted {
		t.Fatalf("POST /register = %d: %s", rec.Code, rec.Body.String())
	} else if got := decodeMap(t, rec); got["verification_required"] != false {
		t.Fatalf("body = %v, want verification_required to be false", got)
	}
}

func TestTheErrorsOfAServiceThatCannotDoItAreNotFound(t *testing.T) {
	a := newTestAuth(t, emailAndUsername())
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, appOrigin+"/x", nil)
	for _, err := range []error{ErrSignupDisabled, ErrRecoveryDisabled} {
		if got := a.failure(r, err); got.code != codeNotFound {
			t.Errorf("%v -> %s, want %s", err, got.code, codeNotFound)
		}
	}
}

func TestTheRequestsOfRecoveryAreLimitedPerClient(t *testing.T) {
	for _, path := range []string{"/register", "/verify", "/password/reset"} {
		f := newRecoveryFixture(t, WithSignup(), WithRecoveryLimits(RecoveryLimits{IPRequests: Limit{Attempts: 2}}))
		api := &apiFixture{handler: f.a.Handler()}
		body := func(i int) any {
			email := fmt.Sprintf("visitor%d@example.com", i)
			if path == "/register" {
				return registration(email, fmt.Sprintf("visitor_%d", i))
			}
			return map[string]string{"login": email}
		}
		for i := range 2 {
			if rec := api.send(t, http.MethodPost, path, body(i), fromAddress("198.51.100.1:1000")); rec.Code != http.StatusAccepted {
				t.Fatalf("POST %s %d = %d: %s", path, i, rec.Code, rec.Body.String())
			}
		}
		rec := api.send(t, http.MethodPost, path, body(2), fromAddress("198.51.100.1:2000"))
		api.expectError(t, rec, http.StatusTooManyRequests, "rate_limited")
		if rec.Header().Get("Retry-After") == "" {
			t.Fatalf("POST %s: no Retry-After", path)
		}
		if rec = api.send(t, http.MethodPost, path, body(3), fromAddress("198.51.100.9:1000")); rec.Code != http.StatusAccepted {
			t.Fatalf("POST %s from another client = %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestAResetRequestAndTheNoticeCarryTheLanguageOfTheClient(t *testing.T) {
	f, api := newRecoveryAPI(t)
	f.verify(t, "email", "nina@example.com")
	api.send(t, http.MethodPost, "/password/reset", map[string]string{"login": "nina_n"}, header("Accept-Language", "ru;q=0.9, en;q=0.5"))
	m := f.ofKind(t, MessagePasswordReset, 1)[0]
	if m.Language != "ru" {
		t.Fatalf("message = %+v, want it in Russian", m)
	}
	body := map[string]string{"channel": "nina@example.com", "code": m.Code, "password": resetPassword}
	if rec := api.send(t, http.MethodPost, "/password/reset/confirm", body); rec.Code != http.StatusNoContent {
		t.Fatalf("POST /password/reset/confirm by channel = %d: %s", rec.Code, rec.Body.String())
	}
	if notice := f.ofKind(t, MessagePasswordChanged, 1)[0]; notice.Language != "en" {
		t.Fatalf("notice = %+v, want English: the request of the confirmation named no language", notice)
	}
	if _, err := f.signIn(t, "nina_n", resetPassword); err != nil {
		t.Fatal(err)
	}
}
