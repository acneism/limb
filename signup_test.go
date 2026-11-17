package limb

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/internal/memstore"
	"github.com/acneism/limb/store"
)

func newSignupFixture(t *testing.T, opts ...Option) *recoveryFixture {
	t.Helper()
	return newRecoveryFixture(t, append([]Option{WithSignup(), manyRequests()}, opts...)...)
}

func (f *recoveryFixture) signup(t *testing.T, fields map[string]string) error {
	t.Helper()
	return f.a.Signup(t.Context(), SignupRequest{Registration: Registration{Identifiers: fields, Password: goodPassword}, IP: ipOne})
}

func (f *recoveryFixture) exists(t *testing.T, typ, value string) bool {
	t.Helper()
	_, err := f.a.store.Identifiers().Find(t.Context(), f.a.tenant, typ, value)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func (f *recoveryFixture) wantNothingCreated(t *testing.T, typ, value string) {
	t.Helper()
	if f.exists(t, typ, value) {
		t.Fatalf("the %s %q was stored", typ, value)
	}
}

func asInvalid(t *testing.T, err error, field string) *ValidationError {
	t.Helper()
	var invalid *ValidationError
	if !errors.As(err, &invalid) || invalid.Field != field {
		t.Fatalf("err = %v, want a *ValidationError for %q", err, field)
	}
	return invalid
}

func wantInvalid(t *testing.T, err error, field string) {
	t.Helper()
	_ = asInvalid(t, err, field)
}

func TestSignupIsClosedUnlessTheServiceOpensIt(t *testing.T) {
	f := newRecoveryFixture(t, manyRequests())
	err := f.signup(t, map[string]string{"email": "olga@example.com"})
	if !errors.Is(err, ErrSignupDisabled) {
		t.Fatalf("Signup = %v, want ErrSignupDisabled", err)
	}
	f.wantNothingCreated(t, "email", "olga@example.com")
	f.noMessages(t)
	if _, err = f.a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "olga@example.com"}, Password: goodPassword}); err != nil {
		t.Fatalf("Register must work whether or not signup is open: %v", err)
	}
}

func TestASignupMakesAnUnconfirmedUserAndSendsTheMessageThatConfirmsIt(t *testing.T) {
	f := newSignupFixture(t)
	err := f.a.Signup(t.Context(), SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": "  Olga@Example.com ", "username": "olga_o"}, Password: goodPassword},
		IP:           ipOne, Language: "ru",
	})
	if err != nil {
		t.Fatalf("Signup = %v", err)
	}
	events := f.events.take()
	wantTypes(t, events, EventUserCreated)
	if events[0].UserID == "" || events[0].IP != ipOne.String() {
		t.Fatalf("event = %+v", events[0])
	}
	m := f.messages(t, 1)[0]
	if m.Kind != MessageVerification || m.UserID != events[0].UserID || m.Channel != "email" || m.To != "olga@example.com" || m.Language != "ru" ||
		!strings.HasPrefix(m.Link, "https://app.example.com/verify#token=") || !sixDigitCode.MatchString(m.Code) {
		t.Fatalf("message = %+v", m)
	}
	email := f.a.mustFind(t, "email", "olga@example.com")
	if !email.VerifiedAt.IsZero() || email.DisplayValue != "Olga@Example.com" {
		t.Fatalf("identifier = %+v, want it unconfirmed and shown as the visitor wrote it", email)
	}
	if _, err = f.signIn(t, "olga_o", "not the password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a wrong password = %v, want ErrInvalidCredentials", err)
	}
	if _, err = f.signIn(t, "olga_o", goodPassword); !errors.Is(err, ErrVerificationRequired) {
		t.Fatalf("sign-in before the confirmation = %v, want ErrVerificationRequired", err)
	}
	if err = f.a.Verify(t.Context(), VerifyRequest{Login: "olga_o", Code: m.Code, IP: ipOne}); err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if _, err = f.signIn(t, "olga_o", goodPassword); err != nil {
		t.Fatalf("sign-in after the confirmation = %v", err)
	}
}

func (a *Auth) mustFind(t *testing.T, typ, value string) store.Identifier {
	t.Helper()
	found, err := a.store.Identifiers().Find(t.Context(), a.tenant, typ, value)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestAnAddressThatIsTakenGetsANoticeAndTheVisitorSeesNothingOfIt(t *testing.T) {
	f := newSignupFixture(t)
	if err := f.signup(t, map[string]string{"email": "olga@example.com", "username": "olga_o"}); err != nil {
		t.Fatal(err)
	}
	f.messages(t, 1)
	f.sender.clear()
	f.events.take()
	err := f.a.Signup(t.Context(), SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": " NINA@example.com ", "username": "other_o"}, Password: goodPassword},
		IP:           ipOne, Language: "ru",
	})
	if err != nil {
		t.Fatalf("Signup with a taken address = %v, want the same nil that a free one gives", err)
	}
	f.wantNothingCreated(t, "username", "other_o")
	notice := f.ofKind(t, MessageSignupAttempt, 1)[0]
	if notice.To != "nina@example.com" || notice.Channel != "email" || notice.UserID != string(f.user.ID) || notice.Language != "ru" ||
		notice.Code != "" || notice.Link != "" || !strings.Contains(notice.Subject, "Acme") {
		t.Fatalf("notice = %+v", notice)
	}
	if events := f.events.take(); len(events) != 0 {
		t.Fatalf("events = %+v, want none: nobody was created", events)
	}
	owner, err := f.a.store.Identifiers().ListByUser(t.Context(), f.a.tenant, string(f.user.ID))
	if err != nil || len(owner) != 2 {
		t.Fatalf("identifiers of the owner = %+v, %v; the attempt must not touch the account", owner, err)
	}
}

func TestATakenNicknameIsReportedWhateverTheAddressIs(t *testing.T) {
	for name, email := range map[string]string{"a free address": "olga@example.com", "a taken address": "nina@example.com"} {
		f := newSignupFixture(t)
		err := f.signup(t, map[string]string{"email": email, "username": "NINA_N"})
		invalid := asInvalid(t, err, "username")
		if invalid.Reason != "already taken" {
			t.Errorf("%s: reason = %q", name, invalid.Reason)
		}
		f.noMessages(t)
		f.wantNothingCreated(t, "email", "olga@example.com")
		if events := f.events.take(); len(events) != 0 {
			t.Errorf("%s: events = %+v", name, events)
		}
	}
}

func TestASignupHashesThePasswordWhetherOrNotTheAddressIsTaken(t *testing.T) {
	f := newSignupFixture(t)
	counting := &countingHasher{passwordHasher: f.a.hasher}
	f.a.hasher = counting
	if err := f.signup(t, map[string]string{"email": "olga@example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := counting.hashes.Load(); got != 1 {
		t.Fatalf("hashes after a free address = %d, want 1", got)
	}
	if err := f.signup(t, map[string]string{"email": "nina@example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := counting.hashes.Load(); got != 2 {
		t.Fatalf("hashes after a taken address = %d, want 2: both do the same work", got)
	}
}

func TestOnlyTheFirstTakenValueGetsANoticeWhenTwoAreTaken(t *testing.T) {
	f := newSignupFixture(t)
	f.addPhone(t)
	other := mustRegister(t, f.a, map[string]string{"email": "boris@example.com", "username": "boris_b"}, goodPassword)
	err := f.signup(t, map[string]string{"email": "boris@example.com", "sms": ninaPhone, "username": "olga_o"})
	if err != nil {
		t.Fatalf("Signup = %v", err)
	}
	f.wantNothingCreated(t, "username", "olga_o")
	got := f.ofKind(t, MessageSignupAttempt, 1)
	if got[0].To != "boris@example.com" || got[0].UserID != string(other.ID) {
		t.Fatalf("notices = %+v, want the one for the first taken value only: the registration stops there", got)
	}
}

func TestSignupAsksForAnAddressToConfirmOnlyWhenTheServiceNeedsOne(t *testing.T) {
	username := identifier.Username(identifier.Required())
	email := identifier.Email()
	f := newRecoveryFixture(t, WithIdentifiers(username, email), WithSignup(), manyRequests())
	err := f.signup(t, map[string]string{"username": "olga_o"})
	invalid := asInvalid(t, err, "identifiers")
	if !strings.Contains(invalid.Reason, "confirm") {
		t.Fatalf("reason = %q", invalid.Reason)
	}
	f.wantNothingCreated(t, "username", "olga_o")
	g := newRecoveryFixture(t, WithIdentifiers(username, email), WithSignup(), WithoutVerificationRequired(), manyRequests())
	if err = g.signup(t, map[string]string{"username": "olga_o"}); err != nil {
		t.Fatalf("without the requirement: %v", err)
	}
	g.noMessages(t)
	if _, err = g.signIn(t, "olga_o", goodPassword); err != nil {
		t.Fatalf("a user may sign in without a confirmed address: %v", err)
	}
	if err = g.signup(t, map[string]string{"username": "ivan_i", "email": "ivan@example.com"}); err != nil {
		t.Fatal(err)
	}
	if m := g.messages(t, 1)[0]; m.Kind != MessageVerification || m.To != "ivan@example.com" {
		t.Fatalf("message = %+v: the confirmation is still sent when it is not required", m)
	}
	if _, err = g.signIn(t, "ivan_i", goodPassword); err != nil {
		t.Fatalf("a user who has not confirmed the address yet may sign in: %v", err)
	}
}

func TestAVisitorCannotConfirmAnAddressBySayingSo(t *testing.T) {
	f := newSignupFixture(t)
	err := f.a.Signup(t.Context(), SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": "olga@example.com"}, Password: goodPassword, Verified: []string{"email"}},
		IP:           ipOne,
	})
	wantInvalid(t, err, "verified")
	f.wantNothingCreated(t, "email", "olga@example.com")
	f.noMessages(t)
}

func TestSignupChecksWhatTheVisitorGave(t *testing.T) {
	f := newSignupFixture(t)
	long := strings.Repeat("v", 1025)
	cases := map[string]struct {
		request SignupRequest
		field   string
	}{
		"an unknown type": {SignupRequest{Registration: Registration{Identifiers: map[string]string{"email": "olga@example.com", "fax": "1"}}}, "fax"},
		"no address":      {SignupRequest{Registration: Registration{Identifiers: map[string]string{"username": "olga_o"}}}, "email"},
		"a bad address":   {SignupRequest{Registration: Registration{Identifiers: map[string]string{"email": "olga"}}}, "email"},
		"too many extras": {SignupRequest{Registration: Registration{Identifiers: map[string]string{"email": "olga@example.com"}, Extra: manyExtras(17)}}, "extra"},
		"a name in capitals": {SignupRequest{Registration: Registration{
			Identifiers: map[string]string{"email": "olga@example.com"}, Extra: map[string]string{"Invite": "x"}}}, "extra"},
		"an empty name": {SignupRequest{Registration: Registration{
			Identifiers: map[string]string{"email": "olga@example.com"}, Extra: map[string]string{"": "x"}}}, "extra"},
		"a long name": {SignupRequest{Registration: Registration{
			Identifiers: map[string]string{"email": "olga@example.com"}, Extra: map[string]string{strings.Repeat("a", 65): "x"}}}, "extra"},
		"a name with a space": {SignupRequest{Registration: Registration{
			Identifiers: map[string]string{"email": "olga@example.com"}, Extra: map[string]string{"in vite": "x"}}}, "extra"},
		"a long value": {SignupRequest{Registration: Registration{
			Identifiers: map[string]string{"email": "olga@example.com"}, Extra: map[string]string{"invite": long}}}, "extra"},
		"a value that is not text": {SignupRequest{Registration: Registration{
			Identifiers: map[string]string{"email": "olga@example.com"}, Extra: map[string]string{"invite": "a\xffb"}}}, "extra"},
		"a control character": {SignupRequest{Registration: Registration{
			Identifiers: map[string]string{"email": "olga@example.com"}, Extra: map[string]string{"invite": "a\nb"}}}, "extra"},
		"a NUL": {SignupRequest{Registration: Registration{
			Identifiers: map[string]string{"email": "olga@example.com"}, Extra: map[string]string{"invite": "a\x00b"}}}, "extra"},
		"a line separator": {SignupRequest{Registration: Registration{
			Identifiers: map[string]string{"email": "olga@example.com"}, Extra: map[string]string{"invite": "a" + string(rune(0x2028)) + "b"}}}, "extra"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c.request.Password, c.request.IP = goodPassword, ipOne
			wantInvalid(t, f.a.Signup(t.Context(), c.request), c.field)
		})
	}
	var policy *PolicyError
	err := f.a.Signup(t.Context(), SignupRequest{Registration: Registration{Identifiers: map[string]string{"email": "olga@example.com"}, Password: "short"}, IP: ipOne})
	if !errors.As(err, &policy) {
		t.Fatalf("a weak password = %v, want a *PolicyError", err)
	}
	f.wantNothingCreated(t, "email", "olga@example.com")
	f.noMessages(t)
}

func netipFor(i int) netip.Addr {
	return netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", 100+i))
}

func manyExtras(n int) map[string]string {
	extra := make(map[string]string, n)
	for i := range n {
		extra[fmt.Sprintf("key%d", i)] = "x"
	}
	return extra
}

func TestSignupAcceptsExtraDataAtItsLimits(t *testing.T) {
	var seen Registration
	f := newSignupFixture(t)
	f.a.hooks.BeforeRegister = func(_ context.Context, r Registration) error {
		seen = r
		return nil
	}
	extra := manyExtras(14)
	extra[strings.Repeat("a", 64)] = strings.Repeat("я", 512)
	extra["a.b_c-9"] = ""
	err := f.a.Signup(t.Context(), SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": "olga@example.com"}, Password: goodPassword, Extra: extra}, IP: ipOne,
	})
	if err != nil {
		t.Fatalf("16 entries, a name of 64 characters and a value of 1024 bytes = %v, want them accepted", err)
	}
	if len(seen.Extra) != 16 || len(seen.Extra[strings.Repeat("a", 64)]) != 1024 {
		t.Fatalf("the hook saw %d entries", len(seen.Extra))
	}
}

func TestAnInvalidSignupIsNotCounted(t *testing.T) {
	f := newRecoveryFixture(t, WithSignup(), WithRecoveryLimits(RecoveryLimits{IPRequests: Limit{Attempts: 2}}))
	for range 6 {
		wantInvalid(t, f.signup(t, map[string]string{"email": "not an address"}), "email")
	}
	for i := range 2 {
		if err := f.signup(t, map[string]string{"email": fmt.Sprintf("visitor%d@example.com", i)}); err != nil {
			t.Fatalf("signup %d = %v", i, err)
		}
	}
	asRateLimit(t, f.signup(t, map[string]string{"email": "visitor9@example.com"}))
	f.wantNothingCreated(t, "email", "visitor9@example.com")
	err := f.a.Signup(t.Context(), SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": "visitor9@example.com"}, Password: goodPassword}, IP: ipTwo,
	})
	if err != nil {
		t.Fatalf("another address of the client = %v", err)
	}
}

func TestSignupCountsTheAddressesLikeTheRequestsForTheirConfirmation(t *testing.T) {
	f := newRecoveryFixture(t, WithSignup())
	for range 3 {
		f.requestVerification(t, "olga@example.com")
	}
	err := f.a.Signup(t.Context(), SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": "olga@example.com"}, Password: goodPassword}, IP: ipTwo,
	})
	asRateLimit(t, err)
	f.wantNothingCreated(t, "email", "olga@example.com")
}

func TestARegistrationIsLimitedAlikeForATakenAndAFreeAddress(t *testing.T) {
	outcomes := func(email string) []string {
		f := newRecoveryFixture(t, WithSignup())
		var got []string
		for i := range 5 {
			err := f.a.Signup(t.Context(), SignupRequest{
				Registration: Registration{Identifiers: map[string]string{"email": email, "username": fmt.Sprintf("n_%d_x", i)}, Password: goodPassword},
				IP:           netipFor(i),
			})
			switch {
			case err == nil:
				got = append(got, "ok")
			case errors.Is(err, ErrRateLimited):
				got = append(got, "limited")
			default:
				got = append(got, err.Error())
			}
		}
		return got
	}
	free, taken := outcomes("olga@example.com"), outcomes("nina@example.com")
	if !slices.Equal(free, taken) || !slices.Equal(free, []string{"ok", "ok", "ok", "limited", "limited"}) {
		t.Fatalf("free = %v, taken = %v", free, taken)
	}
}

func TestEveryAddressAndPhoneNumberOfARegistrationIsCounted(t *testing.T) {
	f := newRecoveryFixture(t, WithSignup())
	for i := range 3 {
		err := f.a.Signup(t.Context(), SignupRequest{
			Registration: Registration{
				Identifiers: map[string]string{"email": fmt.Sprintf("visitor%d@example.com", i), "sms": "+79990001122"}, Password: goodPassword,
			},
			IP: netipFor(i),
		})
		if err != nil {
			t.Fatalf("signup %d = %v", i, err)
		}
	}
	err := f.a.Signup(t.Context(), SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": "visitor9@example.com", "sms": "+79990001122"}, Password: goodPassword},
		IP:           netipFor(9),
	})
	asRateLimit(t, err)
	f.wantNothingCreated(t, "email", "visitor9@example.com")
}

func TestOnlyAddressesAndPhoneNumbersUseUpTheLimitsOfARequest(t *testing.T) {
	f := newRecoveryFixture(t, WithSignup())
	for i := range 6 {
		err := f.a.Signup(t.Context(), SignupRequest{
			Registration: Registration{Identifiers: map[string]string{"email": fmt.Sprintf("visitor%d@example.com", i), "username": "same_nick"}, Password: goodPassword},
			IP:           netipFor(i),
		})
		if i == 0 && err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			wantInvalid(t, err, "username")
		}
	}
}

func TestTheHookSeesANormalizedCopyThatItCannotUseToChangeTheRequest(t *testing.T) {
	f := newSignupFixture(t)
	var seen Registration
	f.a.hooks.BeforeRegister = func(_ context.Context, r Registration) error {
		seen = r
		r.Extra["invite"] = "changed by the hook"
		r.Identifiers["email"] = "changed@example.com"
		return nil
	}
	extra := map[string]string{"invite": "welcome-2026"}
	err := f.a.Signup(t.Context(), SignupRequest{
		Registration: Registration{
			Identifiers: map[string]string{"email": "  Olga@Example.com ", "username": "Olga_O"}, Password: goodPassword, Extra: extra,
		},
		IP: ipOne,
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen.Password != "" || seen.Verified != nil || seen.Extra["invite"] != "changed by the hook" {
		t.Fatalf("hook saw %+v", seen)
	}
	if extra["invite"] != "welcome-2026" {
		t.Fatal("the hook changed the extra data of the caller")
	}
	if !f.exists(t, "email", "olga@example.com") || f.exists(t, "email", "changed@example.com") {
		t.Fatal("the hook changed what is stored")
	}
	g := newSignupFixture(t)
	g.a.hooks.BeforeRegister = func(_ context.Context, r Registration) error {
		seen = r
		return nil
	}
	if err = g.signup(t, map[string]string{"email": "  Olga@Example.com ", "username": "Olga_O"}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"email": "olga@example.com", "username": "olga_o"}
	if len(seen.Identifiers) != 2 || seen.Identifiers["email"] != want["email"] || seen.Identifiers["username"] != want["username"] || seen.Extra != nil {
		t.Fatalf("hook saw %+v, want the normalized identifiers %v and no extra data", seen, want)
	}
}

func TestTheHookIsCalledAfterTheLimitsAndBeforeTheStoreIsAskedAboutUsers(t *testing.T) {
	f := newRecoveryFixture(t, WithSignup(), WithRecoveryLimits(RecoveryLimits{IPRequests: Limit{Attempts: 1}}))
	log := &accessLog{Store: f.a.store}
	f.a.store = log
	var calls int
	var touched []string
	f.a.hooks.BeforeRegister = func(context.Context, Registration) error {
		calls++
		touched = log.taken()
		return nil
	}
	if err := f.signup(t, map[string]string{"email": "nina@example.com", "username": "other_o"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !slices.Contains(touched, "attempts") {
		t.Fatalf("the hook ran %d times after %v: the limits come first", calls, touched)
	}
	for _, name := range []string{"users", "identifiers", "secrets", "transaction"} {
		if slices.Contains(touched, name) {
			t.Errorf("the store was asked about %q before the hook ran: %v", name, touched)
		}
	}
	asRateLimit(t, f.signup(t, map[string]string{"email": "olga@example.com"}))
	if calls != 1 {
		t.Fatalf("the hook ran %d times, a request that the limits turned down must not reach it", calls)
	}
}

func TestTheHookRunsOnceForATakenAndForAFreeAddress(t *testing.T) {
	f := newSignupFixture(t)
	var calls int
	f.a.hooks.BeforeRegister = func(context.Context, Registration) error {
		calls++
		return nil
	}
	for _, email := range []string{"olga@example.com", "nina@example.com"} {
		if err := f.signup(t, map[string]string{"email": email}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("the hook ran %d times for two registrations", calls)
	}
}

func TestWhatTheHookReturnsDecidesTheAnswer(t *testing.T) {
	logger, logs := capturingLogger()
	f := newSignupFixture(t, WithLogger(logger))
	refuse := func(err error) {
		f.a.hooks.BeforeRegister = func(context.Context, Registration) error { return err }
	}

	refuse(&ValidationError{Field: "extra.invite", Reason: "unknown invitation"})
	invalid := asInvalid(t, f.signup(t, map[string]string{"email": "olga@example.com"}), "extra.invite")
	if invalid.Reason != "unknown invitation" {
		t.Fatalf("reason = %q", invalid.Reason)
	}

	refuse(fmt.Errorf("the check of the invitation: %w", &ValidationError{Field: "extra.invite", Reason: "expired"}))
	err := f.signup(t, map[string]string{"email": "olga@example.com"})
	if invalid = asInvalid(t, err, "extra.invite"); invalid.Reason != "expired" || strings.Contains(err.Error(), "the check of the invitation") {
		t.Fatalf("err = %v, want the *ValidationError as it is", err)
	}

	refuse(errors.New("the invitation service is down"))
	err = f.signup(t, map[string]string{"email": "olga@example.com"})
	if !errors.Is(err, ErrRegistrationRefused) || strings.Contains(err.Error(), "invitation service") {
		t.Fatalf("err = %v, want ErrRegistrationRefused without the text of the cause", err)
	}
	if !strings.Contains(logs.String(), "the invitation service is down") {
		t.Fatalf("the cause was not logged:\n%s", logs.String())
	}

	f.a.hooks.BeforeRegister = func(context.Context, Registration) error { panic("the invitation code is welcome-2026") }
	err = f.signup(t, map[string]string{"email": "olga@example.com"})
	if !errors.Is(err, ErrRegistrationRefused) {
		t.Fatalf("a panic = %v, want ErrRegistrationRefused", err)
	}
	if strings.Contains(logs.String(), "welcome-2026") || !strings.Contains(logs.String(), "panic_type=string") {
		t.Fatalf("the log must name the type of the panic and not its value:\n%s", logs.String())
	}

	f.wantNothingCreated(t, "email", "olga@example.com")
	f.noMessages(t)
	if events := f.events.take(); len(events) != 0 {
		t.Fatalf("events = %+v", events)
	}
	refuse(nil)
	if err = f.signup(t, map[string]string{"email": "olga@example.com"}); err != nil {
		t.Fatalf("a hook that agrees = %v", err)
	}
	if !f.exists(t, "email", "olga@example.com") {
		t.Fatal("the user was not created")
	}
}

func TestASignupSucceedsWhenTheQueueIsFullAndTheUserAsksAgain(t *testing.T) {
	logger, logs := capturingLogger()
	f := newSignupFixture(t, WithLogger(logger), WithSending(SendingOptions{Workers: 1, Queue: 1}))
	release := f.block(t)
	f.requestVerification(t, "nina_n")
	if err := f.signup(t, map[string]string{"email": "olga@example.com", "username": "olga_o"}); err != nil {
		t.Fatalf("Signup with a full queue = %v, want it to succeed", err)
	}
	if err := f.signup(t, map[string]string{"email": "nina@example.com", "username": "other_o"}); err != nil {
		t.Fatalf("Signup with a taken address and a full queue = %v, want the same nil", err)
	}
	if !f.exists(t, "email", "olga@example.com") {
		t.Fatal("the user was not created")
	}
	if !strings.Contains(logs.String(), "the message that confirms a new user is not queued") || !strings.Contains(logs.String(), "the notice of a signup attempt is not queued") {
		t.Fatalf("log:\n%s", logs.String())
	}
	release()
	f.messages(t, 1)
	f.sender.clear()
	f.requestVerification(t, "olga_o")
	if m := f.messages(t, 1)[0]; m.To != "olga@example.com" || m.Kind != MessageVerification {
		t.Fatalf("message = %+v", m)
	}
}

func TestOnlyOneOfTheSignupsForOneAddressCreatesTheUser(t *testing.T) {
	f := newSignupFixture(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			err := f.a.Signup(t.Context(), SignupRequest{
				Registration: Registration{Identifiers: map[string]string{"email": "olga@example.com", "username": fmt.Sprintf("olga_%d", i)}, Password: goodPassword},
				IP:           ipOne,
			})
			if err != nil {
				t.Errorf("Signup %d = %v", i, err)
			}
		})
	}
	wg.Wait()
	created := 0
	for i := range 8 {
		if f.exists(t, "username", fmt.Sprintf("olga_%d", i)) {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d users were created for one address, want 1", created)
	}
	f.idle(t)
	byKind := map[MessageKind]int{}
	for _, m := range f.sender.sent() {
		byKind[m.Kind]++
	}
	if byKind[MessageVerification] != 1 || byKind[MessageSignupAttempt] != 5 {
		t.Fatalf("messages = %v, want one verification and five notices: the owner gets five of a kind in an hour", byKind)
	}
}

func TestAFailureOfTheStoreFailsTheSignupAndLeavesNothing(t *testing.T) {
	broken := errors.New("the database is gone")
	for name, cause := range map[string]error{"users.create": broken, "identifiers.add": broken, "users.create conflict": store.ErrConflict} {
		f := newSignupFixture(t)
		faults := newFaults()
		f.a.store = faultStore{Store: f.a.store, faults: faults}
		faults.set(strings.TrimSuffix(name, " conflict"), cause)
		err := f.signup(t, map[string]string{"email": "olga@example.com", "username": "olga_o"})
		var invalid *ValidationError
		if !errors.Is(err, cause) || errors.As(err, &invalid) {
			t.Fatalf("%s: Signup = %v, want the error of the store", name, err)
		}
		faults.clear()
		f.wantNothingCreated(t, "username", "olga_o")
		f.wantNothingCreated(t, "email", "olga@example.com")
		f.noMessages(t)
		if err = f.signup(t, map[string]string{"email": "olga@example.com", "username": "olga_o"}); err != nil {
			t.Fatalf("%s: the retry = %v", name, err)
		}
	}
}

func TestAFailureToHashFailsTheSignup(t *testing.T) {
	f := newSignupFixture(t)
	broken := errors.New("no memory for the hash")
	f.a.hasher = failingHasher{passwordHasher: f.a.hasher, err: broken}
	if err := f.signup(t, map[string]string{"email": "olga@example.com"}); !errors.Is(err, broken) {
		t.Fatalf("Signup = %v, want the error of the hasher", err)
	}
	f.wantNothingCreated(t, "email", "olga@example.com")
}

func TestTheLanguageOfASignupComesFromTheRequestThenFromTheContext(t *testing.T) {
	f := newSignupFixture(t)
	ctx := ContextWithLanguage(t.Context(), "ru")
	err := f.a.Signup(ctx, SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": "olga@example.com"}, Password: goodPassword}, IP: ipOne,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m := f.messages(t, 1)[0]; m.Language != "ru" {
		t.Fatalf("language = %q, want the one of the context", m.Language)
	}
	f.sender.clear()
	err = f.a.Signup(ctx, SignupRequest{
		Registration: Registration{Identifiers: map[string]string{"email": "boris@example.com"}, Password: goodPassword}, IP: ipOne, Language: "en-GB",
	})
	if err != nil {
		t.Fatal(err)
	}
	if m := f.messages(t, 1)[0]; m.Language != "en" {
		t.Fatalf("language = %q, want the one of the request", m.Language)
	}
}

func TestASignupDoesNotNeedASenderWhenNothingAsksForAConfirmation(t *testing.T) {
	a := newTestAuth(t, WithIdentifiers(identifier.Username(identifier.Required())), WithSignup())
	err := a.Signup(t.Context(), SignupRequest{Registration: Registration{Identifiers: map[string]string{"username": "olga_o"}, Password: goodPassword}, IP: ipOne})
	if err != nil {
		t.Fatalf("Signup = %v", err)
	}
	c := Credentials{Login: "olga_o", Password: goodPassword, Kind: SessionCookie}
	if _, err = a.Login(t.Context(), c); err != nil {
		t.Fatalf("Login = %v: a service without a channel to confirm asks for nothing", err)
	}
}

func TestNewNeedsASenderWhenARegistrationHasToBeConfirmed(t *testing.T) {
	email := WithIdentifiers(identifier.Email(identifier.Required()))
	username := WithIdentifiers(identifier.Username(identifier.Required()))
	cases := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{"a channel, signup and no sender", []Option{email, WithSignup()}, true},
		{"a channel, signup and a sender", []Option{email, WithSignup(), WithSender(&recordingSender{})}, false},
		{"a channel, signup and no requirement", []Option{email, WithSignup(), WithoutVerificationRequired()}, false},
		{"a channel and no signup", []Option{email}, false},
		{"no channel and signup", []Option{username, WithSignup()}, false},
		{"the default identifier and signup", []Option{WithSignup()}, true},
	}
	for _, c := range cases {
		_, err := NewWithStore(memstore.New(), []byte(testKey), append([]Option{WithAutoMigrate(), WithLogger(discardingLogger())}, c.opts...)...)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: New = %v", c.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "WithSender") {
			t.Errorf("%s: the error %q must tell what to do", c.name, err)
		}
	}
}

func TestAConfirmedChannelIsRequiredOnlyWhereTheServiceAsksForIt(t *testing.T) {
	register := func(t *testing.T, opts ...Option) error {
		t.Helper()
		a := newTestAuth(t, append([]Option{WithIdentifiers(identifier.Email(identifier.Required()), identifier.Username())}, opts...)...)
		mustRegister(t, a, map[string]string{"email": "nina@example.com", "username": "nina_n"}, goodPassword)
		_, err := a.Login(t.Context(), Credentials{Login: "nina_n", Password: goodPassword, Kind: SessionCookie})
		return err
	}
	sender := WithSender(&recordingSender{})
	if err := register(t, WithSignup(), sender); !errors.Is(err, ErrVerificationRequired) {
		t.Fatalf("open signup = %v, want ErrVerificationRequired", err)
	}
	if err := register(t, sender); err != nil {
		t.Fatalf("closed signup = %v: users that the code of the application makes are not asked", err)
	}
	if err := register(t, WithSignup(), sender, WithoutVerificationRequired()); err != nil {
		t.Fatalf("open signup without the requirement = %v", err)
	}
}

func TestTheRefusalToSignInWithoutAConfirmedChannelFollowsTheRightPasswordAndTheBlock(t *testing.T) {
	f := newSignupFixture(t)
	for range 8 {
		if _, err := f.signIn(t, "nina_n", goodPassword); !errors.Is(err, ErrVerificationRequired) {
			t.Fatalf("sign-in = %v, want ErrVerificationRequired every time: a right password is not a failure", err)
		}
	}
	events := f.events.take()
	if len(events) != 8 || events[0].Type != EventLoginFailed || events[0].UserID != string(f.user.ID) ||
		events[0].Details["reason"] != "verification_required" || events[0].IP != ipOne.String() {
		t.Fatalf("events = %+v", events)
	}
	list, err := f.a.store.Sessions().ListByUser(t.Context(), f.a.tenant, string(f.user.ID), f.clock.now())
	if err != nil || len(list) != 0 {
		t.Fatalf("sessions = %+v, %v: a refused sign-in opens none", list, err)
	}
	if _, err = f.signIn(t, "nina_n", "a wrong password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a wrong password = %v: nothing may tell that the account has no confirmed channel", err)
	}
	if _, err = f.signIn(t, "ghost_g", goodPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("an unknown login = %v", err)
	}
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	if _, err = f.signIn(t, "nina_n", goodPassword); !errors.Is(err, ErrUserBlocked) {
		t.Fatalf("a blocked user without a confirmed channel = %v, want ErrUserBlocked", err)
	}
}

func TestAnyConfirmedChannelLetsTheUserSignIn(t *testing.T) {
	f := newSignupFixture(t)
	f.addPhone(t)
	f.verify(t, "sms", ninaPhone)
	if _, err := f.signIn(t, "nina_n", goodPassword); err != nil {
		t.Fatalf("one confirmed channel of two = %v", err)
	}
	g := newSignupFixture(t)
	g.verify(t, "email", "nina@example.com")
	if _, err := g.signIn(t, "nina@example.com", goodPassword); err != nil {
		t.Fatalf("the confirmed address = %v", err)
	}
}

func TestAChannelThatCannotBeConfirmedDoesNotCount(t *testing.T) {
	f := newSignupFixture(t)
	err := f.a.store.Identifiers().MarkVerified(t.Context(), f.a.tenant, "username", "nina_n", f.clock.now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.signIn(t, "nina_n", goodPassword); !errors.Is(err, ErrVerificationRequired) {
		t.Fatalf("a nickname that is marked as confirmed = %v, want it not to count: it is not a channel", err)
	}
}

func TestAFailureToReadTheChannelsFailsTheSignInAndIsNotTakenForARefusal(t *testing.T) {
	f := newSignupFixture(t)
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	broken := errors.New("the database is gone")
	faults.set("identifiers.list", broken)
	_, err := f.signIn(t, "nina_n", goodPassword)
	if !errors.Is(err, broken) || errors.Is(err, ErrVerificationRequired) {
		t.Fatalf("sign-in = %v, want the error of the store", err)
	}
	if events := f.events.take(); len(events) != 0 {
		t.Fatalf("events = %+v, a failure of the store is not a refused sign-in", events)
	}
}

func TestTheAddressOfAUserWhoWasConfirmedByTheApplicationNeedsNoMessage(t *testing.T) {
	f := newSignupFixture(t)
	user, err := f.a.Register(t.Context(), Registration{
		Identifiers: map[string]string{"email": "boris@example.com", "username": "boris_b", "sms": "+79990001122"},
		Password:    goodPassword, Verified: []string{"sms", "email", "email"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range user.Identifiers {
		confirmed := got.Type != "username"
		if confirmed != !got.VerifiedAt.IsZero() || (confirmed && !got.VerifiedAt.Equal(user.CreatedAt)) {
			t.Fatalf("identifier = %+v, want the address and the phone confirmed when the user was made and the nickname not", got)
		}
	}
	events := f.events.take()
	wantTypes(t, events, EventUserCreated)
	if events[0].Details["verified"] != "email,sms" {
		t.Fatalf("event = %+v", events[0])
	}
	f.noMessages(t)
	if _, err = f.signIn(t, "boris_b", goodPassword); err != nil {
		t.Fatalf("a user whose address the application confirmed = %v", err)
	}
	stored := f.a.mustFind(t, "email", "boris@example.com")
	if stored.VerifiedAt.IsZero() {
		t.Fatal("the confirmation was not stored")
	}
}

func TestRegisterChecksTheTypesThatItIsToldAreConfirmed(t *testing.T) {
	f := newSignupFixture(t)
	cases := map[string]struct {
		identifiers map[string]string
		verified    []string
	}{
		"an unknown type":           {map[string]string{"email": "boris@example.com"}, []string{"fax"}},
		"a nickname":                {map[string]string{"email": "boris@example.com", "username": "boris_b"}, []string{"username"}},
		"a type without a value":    {map[string]string{"email": "boris@example.com"}, []string{"sms"}},
		"a good type and a bad one": {map[string]string{"email": "boris@example.com"}, []string{"email", "sms"}},
	}
	for name, c := range cases {
		_, err := f.a.Register(t.Context(), Registration{Identifiers: c.identifiers, Password: goodPassword, Verified: c.verified})
		var invalid *ValidationError
		if !errors.As(err, &invalid) || invalid.Field != "verified" {
			t.Errorf("%s: Register = %v, want a *ValidationError for verified", name, err)
		}
	}
	f.wantNothingCreated(t, "email", "boris@example.com")
}

func TestRegisterIgnoresTheExtraData(t *testing.T) {
	f := newSignupFixture(t)
	called := false
	f.a.hooks.BeforeRegister = func(context.Context, Registration) error {
		called = true
		return errors.New("no")
	}
	_, err := f.a.Register(t.Context(), Registration{
		Identifiers: map[string]string{"email": "boris@example.com"}, Password: goodPassword, Extra: map[string]string{"Not Valid": "x\n"},
	})
	if err != nil || called {
		t.Fatalf("Register = %v, hook called = %v: Register is for the code of the application and calls no hook", err, called)
	}
}

func TestTheTimeOfAVisitorsAttemptsIsCountedByTheClockOfTheService(t *testing.T) {
	f := newRecoveryFixture(t, WithSignup(), WithRecoveryLimits(RecoveryLimits{ChannelRequests: Limit{Attempts: 1}}))
	if err := f.signup(t, map[string]string{"email": "olga@example.com"}); err != nil {
		t.Fatal(err)
	}
	asRateLimit(t, f.signup(t, map[string]string{"email": "olga@example.com"}))
	f.clock.advance(time.Hour + time.Second)
	if err := f.signup(t, map[string]string{"email": "olga@example.com"}); err != nil {
		t.Fatalf("after the hour = %v", err)
	}
}

func TestASignupAttemptIsNotToldWhenTheOwnerIsGoneOrCannotBeRead(t *testing.T) {
	f := newSignupFixture(t)
	faults := newFaults()
	f.a.store = faultStore{Store: f.a.store, faults: faults}
	send := func() error {
		return f.a.sendSignupAttempt(t.Context(), "email", "nina@example.com", "en")
	}
	if err := f.a.sendSignupAttempt(t.Context(), "email", "nobody@example.com", "en"); err != nil {
		t.Fatalf("an address that nobody has = %v, want nothing to do", err)
	}
	f.noMessages(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusDeleted })
	if err := send(); err != nil {
		t.Fatalf("a deleted owner = %v, want nothing to do", err)
	}
	f.noMessages(t)
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	if err := send(); err != nil {
		t.Fatalf("a blocked owner = %v", err)
	}
	f.ofKind(t, MessageSignupAttempt, 1)
	broken := errors.New("the database is gone")
	for _, name := range []string{"identifiers.find", "users.get"} {
		faults.set(name, broken)
		if err := send(); !errors.Is(err, broken) {
			t.Fatalf("%s: = %v, want the error of the store", name, err)
		}
		faults.set(name, store.ErrNotFound)
		if err := send(); err != nil {
			t.Fatalf("%s: a record that vanished = %v, want nothing to do", name, err)
		}
		faults.clear()
	}
}

func TestATakenAddressOfAServiceWithoutASenderIsAnsweredLikeAFreeOne(t *testing.T) {
	a := newTestAuth(t, emailAndUsername(), WithSignup(), WithoutVerificationRequired())
	mustRegister(t, a, map[string]string{"email": "nina@example.com", "username": "nina_n"}, goodPassword)
	for _, email := range []string{"nina@example.com", "olga@example.com"} {
		err := a.Signup(t.Context(), SignupRequest{Registration: Registration{Identifiers: map[string]string{"email": email, "username": "x_" + email[:4]}, Password: goodPassword}, IP: ipOne})
		if err != nil {
			t.Fatalf("Signup with %s = %v", email, err)
		}
	}
}

func TestAFailureToMakeTheIDFailsTheSignup(t *testing.T) {
	f := newSignupFixture(t)
	broken := errors.New("no random numbers")
	f.a.newID = func() (string, error) { return "", broken }
	if err := f.signup(t, map[string]string{"email": "olga@example.com"}); !errors.Is(err, broken) {
		t.Fatalf("Signup = %v, want the error of the generator", err)
	}
	f.wantNothingCreated(t, "email", "olga@example.com")
}
