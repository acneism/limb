package admin

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

const newPassword = "another phrase of many words"

func (f *fixture) another(t *testing.T, e enrolled) Opened {
	t.Helper()
	f.nextStep()
	in, _ := f.begin(t, "root")
	opened, err := f.Complete(t.Context(), in, f.code(e.seed), browser)
	if err != nil {
		t.Fatalf("another sign-in failed: %v", err)
	}
	return opened
}

func (f *fixture) resolved(t *testing.T, o Opened) Session {
	t.Helper()
	ses, err := f.Resolve(t.Context(), o.Secret)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	return ses
}

func notAPassword(seed []byte, now time.Time) string {
	valid := map[string]bool{}
	step := totp.Step(now)
	for offset := int64(-totp.Window); offset <= totp.Window; offset++ {
		valid[totp.Code(seed, step+offset)] = true
	}
	for n := 0; ; n++ {
		if candidate := fmt.Sprintf("%0*d", totp.Digits, n); !valid[candidate] {
			return candidate
		}
	}
}

func (f *fixture) state(t *testing.T, login string) func() string {
	t.Helper()
	return func() string {
		a := f.stored(t, login)
		rows, err := f.store.AdminSessions().ListByAdmin(t.Context(), a.TenantID, a.ID, f.clock.read())
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, fmt.Sprintf("%s@%d", r.ID, r.AdminVersion))
		}
		left, err := f.store.Admins().CountRecoveryCodes(t.Context(), a.TenantID, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprint(a.Version, a.PasswordHash, string(a.TOTPSecret), a.TOTPConfirmedAt, a.TOTPLastStep, a.LastLoginAt, ids, left, len(f.records(t)))
	}
}

func TestTheProfileShowsTheAccountAndTheSessionsThatWork(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	other := f.another(t, e)
	f.clock.advance(5 * time.Minute)
	ses := f.resolved(t, e.opened)
	profile, err := f.Profile(t.Context(), ses)
	if err != nil {
		t.Fatalf("Profile failed: %v", err)
	}
	if profile.Account.ID != e.account.ID || profile.Account.Login != "root" || !profile.Account.TOTPBound || profile.Account.RecoveryCodes != RecoveryCodeCount ||
		profile.Account.Disabled || profile.Account.CreatedAt.IsZero() || profile.Account.LastLoginAt.IsZero() {
		t.Fatalf("the account is %+v", profile.Account)
	}
	if len(profile.Sessions) != 2 || profile.Sessions[0].ID != e.opened.ID || !profile.Sessions[0].Current || profile.Sessions[1].ID != other.ID || profile.Sessions[1].Current {
		t.Fatalf("the sessions are %+v, want the oldest first with the current one marked", profile.Sessions)
	}
	if got := profile.Sessions[0]; got.IP != browser.IP || got.UserAgent != browser.UserAgent || got.CreatedAt.IsZero() || got.LastSeenAt.Before(got.CreatedAt) {
		t.Fatalf("a session is %+v", got)
	}

	f.clock.advance(f.idle - time.Minute)
	ses = f.resolved(t, e.opened)
	profile, err = f.Profile(t.Context(), ses)
	if err != nil || len(profile.Sessions) != 1 || !profile.Sessions[0].Current {
		t.Fatalf("a session that was idle for too long is shown: %+v, %v", profile.Sessions, err)
	}

	second := f.enroll(t, "second")
	if profile, err = f.Profile(t.Context(), f.resolved(t, second.opened)); err != nil || len(profile.Sessions) != 1 || profile.Account.Login != "second" {
		t.Fatalf("the sessions of another administrator are shown: %+v, %v", profile, err)
	}
}

func TestAnAdministratorChangesTheirPasswordAndKeepsTheSessionThatAsks(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	other := f.another(t, e)
	ses := f.resolved(t, e.opened)
	before := f.stored(t, "root")
	if err := f.ChangePassword(t.Context(), ses, goodPassword, newPassword, browser); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	after := f.stored(t, "root")
	if after.Version != before.Version+1 || after.PasswordHash == before.PasswordHash || !after.TOTPConfirmedAt.Equal(before.TOTPConfirmedAt) || string(after.TOTPSecret) != string(before.TOTPSecret) {
		t.Fatalf("the account is %+v after %+v", after, before)
	}
	if _, err := f.CheckPassword(t.Context(), "root", newPassword); err != nil {
		t.Fatalf("the new password does not work: %v", err)
	}
	if _, err := f.CheckPassword(t.Context(), "root", goodPassword); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("the old password = %v, want ErrBadCredentials", err)
	}
	if _, err := f.Resolve(t.Context(), e.opened.Secret); err != nil {
		t.Fatalf("the session that asked ended: %v", err)
	}
	if _, err := f.Resolve(t.Context(), other.Secret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the other session = %v, want ErrNoSession", err)
	}
	record := f.record(t, audit.AdminPasswordChanged)
	if record.ActorKind != store.ActorAdmin || record.ActorID != e.account.ID || record.IP != browser.IP || !strings.Contains(record.Details, `"sessions_ended":1`) ||
		strings.Contains(record.Details, newPassword) || strings.Contains(record.Details, goodPassword) {
		t.Fatalf("the change is recorded as %+v", record)
	}
	if err := f.ChangePassword(t.Context(), ses, newPassword, goodPassword, browser); !errors.Is(err, ErrNoSession) {
		t.Fatalf("a change with the session as it was before the change = %v, want ErrNoSession", err)
	}
	if err := f.ChangePassword(t.Context(), f.resolved(t, e.opened), newPassword, goodPassword, browser); err != nil {
		t.Fatalf("a change with the session as it is: %v", err)
	}
}

func TestAPasswordIsNotChangedWithoutTheCurrentOneOrAgainstThePolicy(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "administrator")
	ses := f.resolved(t, e.opened)
	fullwidth := strings.NewReplacer("a", "ａ", "e", "ｅ", "o", "ｏ", "r", "ｒ", "t", "ｔ").Replace(goodPassword)
	cases := []struct {
		name, current, next string
		check               func(err error) bool
	}{
		{"a current password that is wrong", "not the password", newPassword, isWrongPassword},
		{"a current password that is empty", "", newPassword, isWrongPassword},
		{"a wrong password and a new one that is no good", "not the password", "short", isWrongPassword},
		{"a new password that is too short", goodPassword, "short", hasRule("min_length")},
		{"a new password that is empty", goodPassword, "", hasRule("min_length")},
		{"a new password that is too long", goodPassword, strings.Repeat("a", 2000), hasRule("max_length")},
		{"a new password that is common", goodPassword, "password1234", hasRule("common_password")},
		{"a new password that is the login", goodPassword, "administrator", hasRule("login_identifier")},
		{"a new password that is the login in another case", goodPassword, "Administrator", hasRule("login_identifier")},
		{"a new password that is the current one", goodPassword, goodPassword, hasRule(RuleSameAsCurrent)},
		{"a new password that is the current one in another form", goodPassword, fullwidth, hasRule(RuleSameAsCurrent)},
	}
	state := f.state(t, "administrator")
	want := state()
	for _, c := range cases {
		err := f.ChangePassword(t.Context(), ses, c.current, c.next, browser)
		if err == nil || !c.check(err) {
			t.Errorf("%s: the change gave %v", c.name, err)
		}
		if got := state(); got != want {
			t.Errorf("%s: the change that was refused left a trace", c.name)
		}
	}
	if _, err := f.Resolve(t.Context(), e.opened.Secret); err != nil {
		t.Fatalf("the session ended: %v", err)
	}
}

func isWrongPassword(err error) bool {
	var refusal *CredentialsError
	return errors.Is(err, ErrBadCredentials) && errors.As(err, &refusal) && refusal.Reason == "wrong_password" && refusal.AdminID != ""
}

func hasRule(rule string) func(error) bool {
	return func(err error) bool {
		var policy *PolicyError
		return errors.As(err, &policy) && slices.Contains(policy.Rules, rule)
	}
}

func TestNewRecoveryCodesReplaceTheOldOnes(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	other := f.another(t, e)
	ses := f.resolved(t, e.opened)

	state := f.state(t, "root")
	want := state()
	if _, err := f.RenewRecoveryCodes(t.Context(), ses, "not the password", browser); !isWrongPassword(err) {
		t.Fatalf("new codes for a wrong password = %v", err)
	}
	if got := state(); got != want {
		t.Fatal("a request that was refused changed the account")
	}

	codes, err := f.RenewRecoveryCodes(t.Context(), ses, goodPassword, browser)
	if err != nil {
		t.Fatalf("RenewRecoveryCodes failed: %v", err)
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if _, ok := secret.ParseRecoveryCode(code); !ok || seen[code] || slices.Contains(e.codes, code) {
			t.Fatalf("the code %q is not a recovery code, is repeated or is an old one", code)
		}
		seen[code] = true
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("there are %d codes", len(codes))
	}
	if left, leftErr := f.RecoveryCodesLeft(t.Context(), e.account.ID); leftErr != nil || left != RecoveryCodeCount {
		t.Fatalf("there are %d codes left, %v", left, leftErr)
	}
	if _, err = f.Resolve(t.Context(), other.Secret); err != nil {
		t.Fatalf("new codes ended another session: %v", err)
	}
	if f.stored(t, "root").Version != e.admin.Version {
		t.Fatal("new codes changed the version of the account")
	}

	in, _ := f.begin(t, "root")
	if _, err = f.Complete(t.Context(), in, e.codes[0], browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("an old recovery code = %v, want ErrBadFactor", err)
	}
	if opened, completeErr := f.Complete(t.Context(), in, codes[0], browser); completeErr != nil || opened.RecoveryCodes != RecoveryCodeCount-1 {
		t.Fatalf("a new recovery code = %+v, %v", opened, completeErr)
	}
	record := f.record(t, audit.AdminRecoveryCodesRenewed)
	if record.ActorID != e.account.ID || record.IP != browser.IP || !strings.Contains(record.Details, `"recovery_codes":10`) || strings.Contains(record.Details, codes[1]) {
		t.Fatalf("the renewal is recorded as %+v", record)
	}
}

func TestAnotherAuthenticatorIsBoundOnlyWhenItsOneTimePasswordIsRight(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	other := f.another(t, e)
	ses := f.resolved(t, e.opened)
	before := f.stored(t, "root")

	if _, err := f.BeginRebind(t.Context(), ses, "not the password"); !isWrongPassword(err) {
		t.Fatalf("a binding for a wrong password = %v", err)
	}
	rebinding, err := f.BeginRebind(t.Context(), ses, goodPassword)
	if err != nil {
		t.Fatalf("BeginRebind failed: %v", err)
	}
	if rebinding.Token == "" || len(rebinding.Seed) != totp.SecretLength || rebinding.Secret != totp.EncodeSecret(rebinding.Seed) ||
		string(rebinding.Seed) == string(e.seed) || !strings.HasPrefix(rebinding.URI, "otpauth://totp/Acme:root?") || !rebinding.ExpiresAt.Equal(f.clock.read().Add(RebindLifetime)) {
		t.Fatalf("the binding is %+v", rebinding)
	}
	if rebinding.Sealed != nil || strings.Contains(rebinding.Token, rebinding.Secret) {
		t.Fatal("the token shows the seed, or a sealed seed is stored")
	}
	if got := f.stored(t, "root"); got.Version != before.Version || string(got.TOTPSecret) != string(before.TOTPSecret) {
		t.Fatal("a binding that waits changed the account: the authenticator that works must stay")
	}
	again, err := f.OpenRebind(t.Context(), ses, rebinding.Token)
	if err != nil || again.Secret != rebinding.Secret || again.URI != rebinding.URI || !again.ExpiresAt.Equal(rebinding.ExpiresAt) {
		t.Fatalf("a page that is shown again = %+v, %v", again, err)
	}

	wrong := notAPassword(rebinding.Seed, f.clock.read())
	if _, err = f.ConfirmRebind(t.Context(), ses, rebinding.Token, wrong, browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("a wrong one-time password = %v, want ErrBadFactor", err)
	}
	if _, err = f.ConfirmRebind(t.Context(), ses, rebinding.Token, f.code(e.seed), browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("a one-time password of the old authenticator = %v, want ErrBadFactor", err)
	}
	if _, err = f.ConfirmRebind(t.Context(), ses, rebinding.Token, e.codes[0], browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("a recovery code as the confirmation = %v, want ErrBadFactor", err)
	}
	if got := f.stored(t, "root"); got.Version != before.Version || string(got.TOTPSecret) != string(before.TOTPSecret) {
		t.Fatal("a confirmation that was refused changed the account")
	}

	f.nextStep()
	f.nextStep()
	step := f.code(rebinding.Seed)
	codes, err := f.ConfirmRebind(t.Context(), ses, rebinding.Token, " "+step[:3]+" "+step[3:]+" ", browser)
	if err != nil {
		t.Fatalf("ConfirmRebind failed: %v", err)
	}
	after := f.stored(t, "root")
	seed, err := f.keys.OpenTOTP(after.TOTPSecret, after.ID)
	if err != nil || string(seed) != string(rebinding.Seed) || after.Version != before.Version+1 || !after.TOTPConfirmedAt.Equal(f.clock.read()) ||
		!after.LastLoginAt.Equal(before.LastLoginAt) || after.TOTPLastStep != totp.Step(f.clock.read()) {
		t.Fatalf("the account is %+v after the binding", after)
	}
	if len(codes) != RecoveryCodeCount || slices.Contains(e.codes, codes[0]) {
		t.Fatalf("the new recovery codes are %v", codes)
	}
	if _, err = f.Resolve(t.Context(), e.opened.Secret); err != nil {
		t.Fatalf("the session that asked ended: %v", err)
	}
	if _, err = f.Resolve(t.Context(), other.Secret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the other session = %v, want ErrNoSession", err)
	}
	record := f.record(t, audit.AdminTOTPRebound)
	if record.ActorID != e.account.ID || record.IP != browser.IP || !strings.Contains(record.Details, `"sessions_ended":1`) || !strings.Contains(record.Details, `"recovery_codes":10`) ||
		strings.Contains(record.Details, rebinding.Secret) || strings.Contains(record.Details, rebinding.Token) {
		t.Fatalf("the binding is recorded as %+v", record)
	}

	in, _ := f.begin(t, "root")
	if _, err = f.Complete(t.Context(), in, f.code(rebinding.Seed), browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("the one-time password that confirmed the binding, used again = %v, want ErrBadFactor", err)
	}
	if _, err = f.Complete(t.Context(), in, e.codes[1], browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("an old recovery code = %v, want ErrBadFactor", err)
	}
	f.nextStep()
	if _, err = f.Complete(t.Context(), in, f.code(e.seed), browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("a one-time password of the old authenticator = %v, want ErrBadFactor", err)
	}
	in, _ = f.begin(t, "root")
	if _, err = f.Complete(t.Context(), in, f.code(rebinding.Seed), browser); err != nil {
		t.Fatalf("a one-time password of the new authenticator = %v", err)
	}
	in, _ = f.begin(t, "root")
	if _, err = f.Complete(t.Context(), in, codes[0], browser); err != nil {
		t.Fatalf("a new recovery code = %v", err)
	}
	if _, err = f.ConfirmRebind(t.Context(), f.resolved(t, e.opened), rebinding.Token, f.code(rebinding.Seed), browser); !errors.Is(err, ErrNoRebind) {
		t.Fatalf("a token that was used = %v, want ErrNoRebind", err)
	}
}

func TestABindingIsOfOneSessionOfOneAccountAndRunsOut(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	other := f.another(t, e)
	ses := f.resolved(t, e.opened)
	rebinding, err := f.BeginRebind(t.Context(), ses, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	code := f.code(rebinding.Seed)

	otherSession := f.resolved(t, other)
	if _, err = f.OpenRebind(t.Context(), otherSession, rebinding.Token); !errors.Is(err, ErrNoRebind) {
		t.Fatalf("the token of one session in another = %v, want ErrNoRebind", err)
	}
	if _, err = f.ConfirmRebind(t.Context(), otherSession, rebinding.Token, code, browser); !errors.Is(err, ErrNoRebind) {
		t.Fatalf("a confirmation with the token of another session = %v, want ErrNoRebind", err)
	}
	second := f.enroll(t, "second")
	secondSession := f.resolved(t, second.opened)
	if _, err = f.ConfirmRebind(t.Context(), secondSession, rebinding.Token, code, browser); !errors.Is(err, ErrNoRebind) {
		t.Fatalf("the token of one administrator for another = %v, want ErrNoRebind", err)
	}

	for name, token := range map[string]string{
		"an empty token":       "",
		"a token that is cut":  rebinding.Token[:len(rebinding.Token)-2],
		"a token that is long": rebinding.Token + rebinding.Token,
		"a token that is huge": strings.Repeat("A", 100_000),
		"a token with a flip":  flip(rebinding.Token),
		"a token that is junk": "!!!",
		"a token of padding":   rebinding.Token + "=",
		"a token of a seed":    rebinding.Secret,
	} {
		if _, openErr := f.OpenRebind(t.Context(), ses, token); !errors.Is(openErr, ErrNoRebind) {
			t.Errorf("%s: OpenRebind = %v, want ErrNoRebind", name, openErr)
		}
		if _, confirmErr := f.ConfirmRebind(t.Context(), ses, token, code, browser); !errors.Is(confirmErr, ErrNoRebind) {
			t.Errorf("%s: ConfirmRebind = %v, want ErrNoRebind", name, confirmErr)
		}
	}

	f.clock.advance(rebinding.ExpiresAt.Sub(f.clock.read()) - time.Second)
	if _, err = f.OpenRebind(t.Context(), ses, rebinding.Token); err != nil {
		t.Fatalf("a binding a second before its end = %v", err)
	}
	f.clock.advance(time.Second)
	if _, err = f.OpenRebind(t.Context(), ses, rebinding.Token); !errors.Is(err, ErrNoRebind) {
		t.Fatalf("a binding at its end = %v, want ErrNoRebind", err)
	}
	if _, err = f.ConfirmRebind(t.Context(), ses, rebinding.Token, f.code(rebinding.Seed), browser); !errors.Is(err, ErrNoRebind) {
		t.Fatalf("a confirmation at its end = %v, want ErrNoRebind", err)
	}

	fresh, err := f.BeginRebind(t.Context(), ses, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.ChangePassword(t.Context(), ses, goodPassword, newPassword, browser); err != nil {
		t.Fatal(err)
	}
	if _, err = f.OpenRebind(t.Context(), f.resolved(t, e.opened), fresh.Token); !errors.Is(err, ErrNoRebind) {
		t.Fatalf("a binding that the account outlived = %v, want ErrNoRebind: the account changed meanwhile", err)
	}
}

func flip(token string) string {
	middle := len(token) / 2
	replacement := "A"
	if token[middle] == 'A' {
		replacement = "B"
	}
	return token[:middle] + replacement + token[middle+1:]
}

func TestOwnSessionsAreEndedOneByOneOrAllButTheCurrent(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	first, second := f.another(t, e), f.another(t, e)
	ses := f.resolved(t, e.opened)
	stranger := f.enroll(t, "second")

	if err := f.EndSession(t.Context(), ses, first.ID, browser); err != nil {
		t.Fatalf("EndSession failed: %v", err)
	}
	if _, err := f.Resolve(t.Context(), first.Secret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the session that ended = %v", err)
	}
	record := f.record(t, audit.AdminSessionEnded)
	if record.ActorID != e.account.ID || record.IP != browser.IP || !strings.Contains(record.Details, first.ID) || strings.Contains(record.Details, first.Secret) {
		t.Fatalf("the end of the session is recorded as %+v", record)
	}
	for name, id := range map[string]string{
		"the session that asks":              ses.ID,
		"a session that ended":               first.ID,
		"a session that is not there":        "no-such-session",
		"an empty ID":                        "",
		"an ID that is too long":             strings.Repeat("x", store.MaxIDLength+1),
		"a session of another administrator": stranger.opened.ID,
	} {
		if err := f.EndSession(t.Context(), ses, id, browser); !errors.Is(err, ErrNoSuchSession) {
			t.Errorf("%s: EndSession = %v, want ErrNoSuchSession", name, err)
		}
	}
	if _, err := f.Resolve(t.Context(), stranger.opened.Secret); err != nil {
		t.Fatalf("the session of another administrator ended: %v", err)
	}
	if _, err := f.Resolve(t.Context(), e.opened.Secret); err != nil {
		t.Fatalf("the session that asks ended: %v", err)
	}

	count, err := f.EndOtherSessions(t.Context(), ses, browser)
	if err != nil || count != 1 {
		t.Fatalf("EndOtherSessions = %d, %v, want 1", count, err)
	}
	if _, err = f.Resolve(t.Context(), second.Secret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the other session = %v", err)
	}
	ended := f.record(t, audit.AdminSessionsEnded)
	if !strings.Contains(ended.Details, `"sessions_ended":1`) || ended.ActorID != e.account.ID {
		t.Fatalf("the end of the sessions is recorded as %+v", ended)
	}
	if count, err = f.EndOtherSessions(t.Context(), ses, browser); err != nil || count != 0 {
		t.Fatalf("EndOtherSessions with none = %d, %v", count, err)
	}
	f.record(t, audit.AdminSessionsEnded)
	if _, err = f.Resolve(t.Context(), stranger.opened.Secret); err != nil {
		t.Fatalf("the session of another administrator ended: %v", err)
	}
}

func TestTheOperationsOnTheAccountNeedASessionThatWorks(t *testing.T) {
	operations := map[string]func(f *fixture, ses Session) error{
		"Profile": func(f *fixture, ses Session) error {
			_, err := f.Profile(t.Context(), ses)
			return err
		},
		"ChangePassword": func(f *fixture, ses Session) error {
			return f.ChangePassword(t.Context(), ses, goodPassword, newPassword, browser)
		},
		"RenewRecoveryCodes": func(f *fixture, ses Session) error {
			_, err := f.RenewRecoveryCodes(t.Context(), ses, goodPassword, browser)
			return err
		},
		"BeginRebind": func(f *fixture, ses Session) error {
			_, err := f.BeginRebind(t.Context(), ses, goodPassword)
			return err
		},
		"OpenRebind": func(f *fixture, ses Session) error {
			_, err := f.OpenRebind(t.Context(), ses, "token")
			return err
		},
		"ConfirmRebind": func(f *fixture, ses Session) error {
			_, err := f.ConfirmRebind(t.Context(), ses, "token", "123456", browser)
			return err
		},
		"EndSession": func(f *fixture, ses Session) error {
			return f.EndSession(t.Context(), ses, "another", browser)
		},
		"EndOtherSessions": func(f *fixture, ses Session) error {
			_, err := f.EndOtherSessions(t.Context(), ses, browser)
			return err
		},
	}
	changes := map[string]func(f *fixture) error{
		"the password was reset": func(f *fixture) error {
			return f.ResetPassword(t.Context(), audit.CLI, "root", newPassword)
		},
		"the authenticator was reset": func(f *fixture) error { return f.ResetTOTP(t.Context(), audit.CLI, "root") },
		"the account was disabled":    func(f *fixture) error { return f.Disable(t.Context(), audit.CLI, "root") },
		"the account was deleted":     func(f *fixture) error { return f.Delete(t.Context(), audit.CLI, "root") },
	}
	for operation, run := range operations {
		for change, apply := range changes {
			f := newFixture(t)
			e := f.enroll(t, "root")
			ses := f.resolved(t, e.opened)
			if err := apply(f); err != nil {
				t.Fatal(err)
			}
			if err := run(f, ses); !errors.Is(err, ErrNoSession) {
				t.Errorf("%s after %s = %v, want ErrNoSession", operation, change, err)
			}
		}
	}
}

func TestWithoutTheSecondFactorThereIsNoAuthenticatorToChange(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	f.noTOTP = true
	opened, err := f.Open(t.Context(), f.stored(t, "root"), browser)
	if err != nil {
		t.Fatal(err)
	}
	ses := f.resolved(t, opened)
	if _, err = f.RenewRecoveryCodes(t.Context(), ses, goodPassword, browser); !errors.Is(err, ErrNoSecondFactor) {
		t.Fatalf("RenewRecoveryCodes = %v, want ErrNoSecondFactor", err)
	}
	if _, err = f.BeginRebind(t.Context(), ses, goodPassword); !errors.Is(err, ErrNoSecondFactor) {
		t.Fatalf("BeginRebind = %v, want ErrNoSecondFactor", err)
	}
	if _, err = f.OpenRebind(t.Context(), ses, "token"); !errors.Is(err, ErrNoSecondFactor) {
		t.Fatalf("OpenRebind = %v, want ErrNoSecondFactor", err)
	}
	if _, err = f.ConfirmRebind(t.Context(), ses, "token", "123456", browser); !errors.Is(err, ErrNoSecondFactor) {
		t.Fatalf("ConfirmRebind = %v, want ErrNoSecondFactor", err)
	}
	if err = f.ChangePassword(t.Context(), ses, goodPassword, newPassword, browser); err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}
	if profile, profileErr := f.Profile(t.Context(), f.resolved(t, opened)); profileErr != nil || profile.Account.TOTPBound || len(profile.Sessions) != 1 {
		t.Fatalf("Profile = %+v, %v", profile, profileErr)
	}
}

func TestAFailureOfTheStoreAtAnyStepOfAChangeOfTheAccountIsReportedAndChangesNothing(t *testing.T) {
	broken := errors.New("the store failed")
	type prepared struct {
		f   *fixture
		run func() error
	}
	scenarios := map[string]func(t *testing.T) prepared{
		"the profile": func(t *testing.T) prepared {
			f := newFixture(t)
			e := f.enroll(t, "root")
			ses := f.resolved(t, e.opened)
			return prepared{f, func() error {
				_, err := f.Profile(t.Context(), ses)
				return err
			}}
		},
		"a change of the password": func(t *testing.T) prepared {
			f := newFixture(t)
			e := f.enroll(t, "root")
			f.another(t, e)
			ses := f.resolved(t, e.opened)
			return prepared{f, func() error { return f.ChangePassword(t.Context(), ses, goodPassword, newPassword, browser) }}
		},
		"new recovery codes": func(t *testing.T) prepared {
			f := newFixture(t)
			e := f.enroll(t, "root")
			ses := f.resolved(t, e.opened)
			return prepared{f, func() error {
				_, err := f.RenewRecoveryCodes(t.Context(), ses, goodPassword, browser)
				return err
			}}
		},
		"the start of a binding": func(t *testing.T) prepared {
			f := newFixture(t)
			e := f.enroll(t, "root")
			ses := f.resolved(t, e.opened)
			return prepared{f, func() error {
				_, err := f.BeginRebind(t.Context(), ses, goodPassword)
				return err
			}}
		},
		"the page of a binding": func(t *testing.T) prepared {
			f := newFixture(t)
			e := f.enroll(t, "root")
			ses := f.resolved(t, e.opened)
			rebinding, err := f.BeginRebind(t.Context(), ses, goodPassword)
			if err != nil {
				t.Fatal(err)
			}
			return prepared{f, func() error {
				_, openErr := f.OpenRebind(t.Context(), ses, rebinding.Token)
				return openErr
			}}
		},
		"the confirmation of a binding": func(t *testing.T) prepared {
			f := newFixture(t)
			e := f.enroll(t, "root")
			f.another(t, e)
			ses := f.resolved(t, e.opened)
			rebinding, err := f.BeginRebind(t.Context(), ses, goodPassword)
			if err != nil {
				t.Fatal(err)
			}
			f.nextStep()
			f.nextStep()
			code := f.code(rebinding.Seed)
			return prepared{f, func() error {
				_, confirmErr := f.ConfirmRebind(t.Context(), ses, rebinding.Token, code, browser)
				return confirmErr
			}}
		},
		"the end of a session": func(t *testing.T) prepared {
			f := newFixture(t)
			e := f.enroll(t, "root")
			other := f.another(t, e)
			ses := f.resolved(t, e.opened)
			return prepared{f, func() error { return f.EndSession(t.Context(), ses, other.ID, browser) }}
		},
		"the end of the other sessions": func(t *testing.T) prepared {
			f := newFixture(t)
			e := f.enroll(t, "root")
			f.another(t, e)
			ses := f.resolved(t, e.opened)
			return prepared{f, func() error {
				_, err := f.EndOtherSessions(t.Context(), ses, browser)
				return err
			}}
		},
	}
	for name, prepare := range scenarios {
		for failAt := 1; ; failAt++ {
			sc := prepare(t)
			state := sc.f.state(t, "root")
			before := state()
			n := &nth{failAt: failAt, err: broken}
			sc.f.Service.store = nthStore{Store: sc.f.store, n: n}
			err := sc.run()
			sc.f.Service.store = sc.f.store
			if !n.reached() {
				if err != nil {
					t.Errorf("%s: with no failure the call returned %v", name, err)
				}
				if failAt == 1 {
					t.Errorf("%s: the call does not touch the store", name)
				}
				break
			}
			if !errors.Is(err, broken) {
				t.Errorf("%s: the failure of call %d came back as %v", name, failAt, err)
			}
			if after := state(); after != before {
				t.Errorf("%s: the failure of call %d left a trace", name, failAt)
			}
		}
	}
}
