package admin

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

var browser = Client{IP: "198.51.100.7", UserAgent: "Mozilla/5.0 (test)"}

type countingHasher struct {
	Hasher
	verifies atomic.Int64
	dummies  atomic.Int64
	rehash   bool
}

func (h *countingHasher) Verify(ctx context.Context, password, encoded string) (bool, bool, error) {
	h.verifies.Add(1)
	ok, _, err := h.Hasher.Verify(ctx, password, encoded)
	return ok, ok && h.rehash, err
}

func (h *countingHasher) DummyVerify(ctx context.Context, password string) error {
	h.dummies.Add(1)
	return h.Hasher.DummyVerify(ctx, password)
}

func (h *countingHasher) work() int64 {
	return h.verifies.Load() + h.dummies.Load()
}

type enrolled struct {
	account Account
	admin   store.Admin
	seed    []byte
	codes   []string
	opened  Opened
}

func (f *fixture) code(seed []byte) string {
	return totp.Code(seed, totp.Step(f.clock.read()))
}

func (f *fixture) nextStep() {
	f.clock.advance(time.Duration(totp.StepSeconds) * time.Second)
}

func (f *fixture) enroll(t *testing.T, login string) enrolled {
	t.Helper()
	account := f.create(t, login)
	admin := f.stored(t, login)
	pending, err := f.Begin(t.Context(), admin, browser)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	in, err := f.Pending(t.Context(), pending.Secret)
	if err != nil {
		t.Fatalf("Pending failed: %v", err)
	}
	enrollment, err := f.Enroll(t.Context(), in)
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	in, err = f.Pending(t.Context(), pending.Secret)
	if err != nil {
		t.Fatalf("Pending after Enroll failed: %v", err)
	}
	opened, codes, err := f.CompleteEnrollment(t.Context(), in, f.code(enrollment.Seed), browser)
	if err != nil {
		t.Fatalf("CompleteEnrollment failed: %v", err)
	}
	f.nextStep()
	return enrolled{account: account, admin: f.stored(t, login), seed: enrollment.Seed, codes: codes, opened: opened}
}

func (f *fixture) begin(t *testing.T, login string) (SignIn, string) {
	t.Helper()
	admin, err := f.CheckPassword(t.Context(), login, goodPassword)
	if err != nil {
		t.Fatalf("CheckPassword failed: %v", err)
	}
	pending, err := f.Begin(t.Context(), admin, browser)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	in, err := f.Pending(t.Context(), pending.Secret)
	if err != nil {
		t.Fatalf("Pending failed: %v", err)
	}
	return in, pending.Secret
}

func (f *fixture) actions(t *testing.T) []string {
	t.Helper()
	var actions []string
	for _, r := range f.records(t) {
		actions = append(actions, r.Action)
	}
	return actions
}

func (f *fixture) record(t *testing.T, action string) store.AuditRecord {
	t.Helper()
	var found []store.AuditRecord
	for _, r := range f.records(t) {
		if r.Action == action {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the audit log holds %d records of %s, want 1: %v", len(found), action, f.actions(t))
	}
	return found[0]
}

func TestAPasswordOpensAnAccountWhateverTheFormOfTheLogin(t *testing.T) {
	f := newFixture(t)
	account := f.create(t, "root")
	for _, login := range []string{"root", "  Root  ", "ROOT", "ｒｏｏｔ"} {
		a, err := f.CheckPassword(t.Context(), login, goodPassword)
		if err != nil || a.ID != account.ID || a.Login != "root" {
			t.Errorf("CheckPassword(%q) = %+v, %v", login, a, err)
		}
	}
}

func TestEveryRefusalOfAPasswordIsTheSameErrorAfterTheSameWork(t *testing.T) {
	f := newFixture(t)
	counting := &countingHasher{Hasher: f.hasher}
	f.hasher = counting
	root := f.create(t, "root")
	f.create(t, "gone")
	if err := f.Disable(t.Context(), audit.CLI, "gone"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		login, password string
		reason          string
		adminID         string
	}{
		"a wrong password":                   {"root", "not the password at all", "wrong_password", root.ID},
		"a login that does not exist":        {"nobody", goodPassword, "unknown_login", ""},
		"a login that cannot be a login":     {"ro ot", goodPassword, "invalid_login", ""},
		"an empty login":                     {"", goodPassword, "invalid_login", ""},
		"a disabled account":                 {"gone", goodPassword, "disabled", f.stored(t, "gone").ID},
		"a disabled account, wrong password": {"gone", "not the password at all", "wrong_password", f.stored(t, "gone").ID},
		"an empty password":                  {"root", "", "wrong_password", root.ID},
	}
	for name, c := range cases {
		before := counting.work()
		_, err := f.CheckPassword(t.Context(), c.login, c.password)
		var refused *CredentialsError
		if !errors.Is(err, ErrBadCredentials) || !errors.As(err, &refused) || refused.Reason != c.reason || refused.AdminID != c.adminID {
			t.Errorf("%s: CheckPassword = %v, want %q for %q", name, err, c.reason, c.adminID)
		}
		if got := counting.work() - before; got != 1 {
			t.Errorf("%s: %d passwords were hashed, want exactly one: the work must not tell the account", name, got)
		}
	}
}

func TestAPasswordThatCannotBeCheckedIsRefusedAndAHashThatIsWeakIsMadeAgain(t *testing.T) {
	f := newFixture(t)
	counting := &countingHasher{Hasher: f.hasher, rehash: true}
	f.hasher = counting
	root := f.create(t, "root")
	original := f.stored(t, "root")
	a, err := f.CheckPassword(t.Context(), "root", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	stored := f.stored(t, "root")
	if original.Version != 1 || stored.Version != 2 || a.Version != stored.Version || a.PasswordHash != stored.PasswordHash || stored.PasswordHash == original.PasswordHash {
		t.Fatalf("the hash was not made again: stored %+v, returned %+v, before %+v", stored, a, original)
	}
	if ok, _, verifyErr := counting.Hasher.Verify(t.Context(), goodPassword, stored.PasswordHash); verifyErr != nil || !ok {
		t.Fatalf("the new hash does not match the password: %v", verifyErr)
	}

	broken := stored
	broken.PasswordHash = "not an encoded hash"
	if _, err = f.store.Admins().Update(t.Context(), broken); err != nil {
		t.Fatal(err)
	}
	before := counting.work()
	var refused *CredentialsError
	if _, err = f.CheckPassword(t.Context(), "root", goodPassword); !errors.As(err, &refused) || refused.Reason != "unusable_hash" || refused.AdminID != root.ID {
		t.Fatalf("CheckPassword with a hash that cannot be used = %v", err)
	}
	if got := counting.work() - before; got != 2 {
		t.Fatalf("%d passwords were hashed, want the attempt and the work that hides it", got)
	}
}

func TestACheckOfAPasswordThatIsCancelledIsNotARefusal(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	f.hasher = refusingHasher{err: context.Canceled}
	if _, err := f.CheckPassword(t.Context(), "root", goodPassword); !errors.Is(err, context.Canceled) || errors.Is(err, ErrBadCredentials) {
		t.Fatalf("CheckPassword = %v, want the cancellation, which is no wrong password", err)
	}
	if _, err := f.CheckPassword(t.Context(), "nobody", goodPassword); !errors.Is(err, context.Canceled) || errors.Is(err, ErrBadCredentials) {
		t.Fatalf("CheckPassword for a login that does not exist = %v, want the cancellation", err)
	}
}

func TestAnAdministratorBindsAnAuthenticatorAtTheFirstSignIn(t *testing.T) {
	f := newFixture(t)
	account := f.create(t, "root")
	in, secret := f.begin(t, "root")
	if !in.NeedsEnrollment() || in.Session.Stage != store.AdminStagePassword || !in.Session.ExpiresAt.Equal(f.clock.read().Add(PendingLifetime)) {
		t.Fatalf("the sign-in is %+v", in.Session)
	}
	enrollment, err := f.Enroll(t.Context(), in)
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if !strings.HasPrefix(enrollment.URI, "otpauth://totp/Acme:root?") || enrollment.Secret == "" || len(enrollment.Seed) != totp.SecretLength {
		t.Fatalf("the enrollment is %+v", enrollment)
	}
	again, err := f.Pending(t.Context(), secret)
	if err != nil {
		t.Fatalf("the sign-in after the seed was stored = %v: it follows the new version of the account", err)
	}
	second, err := f.Enroll(t.Context(), again)
	if err != nil || second.Secret != enrollment.Secret || second.URI != enrollment.URI {
		t.Fatalf("a page that is shown again has the enrollment %+v, %v, want the same one", second, err)
	}
	if stored := f.stored(t, "root"); len(stored.TOTPSecret) == 0 || !stored.TOTPConfirmedAt.IsZero() || strings.Contains(string(stored.TOTPSecret), string(enrollment.Seed)) {
		t.Fatalf("the seed is stored as %+v, want it sealed and not confirmed", stored)
	}
	if accounts, listErr := f.List(t.Context()); listErr != nil || len(accounts) != 1 || accounts[0].ID != account.ID || accounts[0].TOTPBound {
		t.Fatalf("the accounts are %+v, %v: the authenticator is not bound before the code was confirmed", accounts, listErr)
	}

	wrong := "000000"
	if wrong == f.code(enrollment.Seed) {
		wrong = "000001"
	}
	if _, _, err = f.CompleteEnrollment(t.Context(), again, wrong, browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("CompleteEnrollment with a wrong code = %v, want ErrBadFactor", err)
	}
	if _, _, err = f.CompleteEnrollment(t.Context(), again, "ABCDE-ABCDE-ABCDE-ABCDE-ABCDE", browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("CompleteEnrollment with a recovery code = %v, want ErrBadFactor: there is none yet", err)
	}
	opened, codes, err := f.CompleteEnrollment(t.Context(), again, f.code(enrollment.Seed), browser)
	if err != nil {
		t.Fatalf("CompleteEnrollment failed: %v", err)
	}
	if len(codes) != RecoveryCodeCount || opened.RecoveryCodes != RecoveryCodeCount || opened.Method != "password+totp" || opened.Secret == "" || opened.Secret == secret {
		t.Fatalf("the session is %+v with %d codes: it has a secret of its own", opened, len(codes))
	}
	stored := f.stored(t, "root")
	if stored.TOTPConfirmedAt.IsZero() || !stored.LastLoginAt.Equal(f.clock.read()) {
		t.Fatalf("the administrator is %+v", stored)
	}
	if left, countErr := f.store.Admins().CountRecoveryCodes(t.Context(), store.DefaultTenant, account.ID); countErr != nil || left != RecoveryCodeCount {
		t.Fatalf("the recovery codes that are kept: %d, %v", left, countErr)
	}
	if _, pendingErr := f.Pending(t.Context(), secret); !errors.Is(pendingErr, ErrNoSignIn) {
		t.Fatalf("the sign-in that ended = %v, want ErrNoSignIn: it works once", pendingErr)
	}
	enrolledRecord, loginRecord := f.record(t, audit.AdminTOTPEnrolled), f.record(t, audit.AdminLogin)
	if enrolledRecord.ActorKind != store.ActorAdmin || enrolledRecord.ActorID != account.ID || enrolledRecord.IP != browser.IP || loginRecord.ActorID != account.ID {
		t.Fatalf("the records are %+v and %+v", enrolledRecord, loginRecord)
	}
	if details := loginRecord.Details; !strings.Contains(details, `"method":"password+totp"`) || !strings.Contains(details, opened.ID) {
		t.Fatalf("the sign-in is recorded as %s", details)
	}
	for _, r := range f.records(t) {
		for _, code := range codes {
			if strings.Contains(r.Details, code) || strings.Contains(r.Details, enrollment.Secret) {
				t.Fatalf("the audit log holds a secret: %s", r.Details)
			}
		}
	}
	if _, enrollErr := f.Enroll(t.Context(), SignIn{Session: in.Session, Admin: stored}); !errors.Is(enrollErr, ErrNoSignIn) {
		t.Fatalf("Enroll for an administrator who has an authenticator = %v, want ErrNoSignIn", enrollErr)
	}
}

func TestTheSecondFactorOpensASessionThatHasASecretOfItsOwn(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	in, pendingSecret := f.begin(t, "root")
	if in.NeedsEnrollment() {
		t.Fatal("an administrator who has an authenticator is asked to bind one")
	}
	opened, err := f.Complete(t.Context(), in, f.code(e.seed), browser)
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if opened.Method != "password+totp" || opened.Secret == pendingSecret || opened.AdminID != e.account.ID || opened.Login != "root" ||
		!opened.ExpiresAt.Equal(f.clock.read().Add(12*time.Hour)) || opened.IP != browser.IP || opened.UserAgent != browser.UserAgent {
		t.Fatalf("the session is %+v", opened)
	}
	if _, err = f.Pending(t.Context(), pendingSecret); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("the sign-in after it succeeded = %v, want ErrNoSignIn", err)
	}
	if _, err = f.Resolve(t.Context(), pendingSecret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the secret of a sign-in as the secret of a session = %v, want ErrNoSession", err)
	}
	resolved, err := f.Resolve(t.Context(), opened.Secret)
	if err != nil || resolved.ID != opened.ID || resolved.Login != "root" {
		t.Fatalf("Resolve = %+v, %v", resolved, err)
	}
	if _, err = f.Pending(t.Context(), opened.Secret); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("the secret of a session as the secret of a sign-in = %v, want ErrNoSignIn", err)
	}
	if got := f.stored(t, "root").LastLoginAt; !got.Equal(f.clock.read()) {
		t.Fatalf("the last sign-in is %v", got)
	}
	record := f.records(t)[0]
	if record.Action != audit.AdminLogin || record.ActorID != e.account.ID || record.IP != browser.IP || !strings.Contains(record.Details, "password+totp") {
		t.Fatalf("the newest record is %+v", record)
	}
}

func TestAOneTimePasswordWorksOnceAndTheNextOneWorksAStepLater(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	in, _ := f.begin(t, "root")
	if _, err := f.Complete(t.Context(), in, f.code(e.seed), browser); err != nil {
		t.Fatal(err)
	}
	again, _ := f.begin(t, "root")
	if _, err := f.Complete(t.Context(), again, f.code(e.seed), browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("the same one-time password again = %v, want ErrBadFactor", err)
	}
	f.nextStep()
	if _, err := f.Complete(t.Context(), again, f.code(e.seed), browser); err != nil {
		t.Fatalf("the next one-time password = %v", err)
	}
	var records int
	for _, r := range f.records(t) {
		if r.Action == audit.AdminLogin {
			records++
		}
	}
	if records != 3 {
		t.Fatalf("%d sign-ins were recorded, want 3: the enrollment and two with the code", records)
	}
}

func TestAWrongSecondFactorIsRefusedThreeTimesAndThenTheSignInEnds(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	in, secret := f.begin(t, "root")
	for i := range MaxGuesses {
		if _, err := f.Complete(t.Context(), in, "000000", browser); !errors.Is(err, ErrBadFactor) {
			t.Fatalf("guess %d = %v, want ErrBadFactor", i+1, err)
		}
	}
	if _, err := f.Complete(t.Context(), in, f.code(e.seed), browser); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("the right code after the guesses were used = %v, want ErrNoSignIn", err)
	}
	if _, err := f.Pending(t.Context(), secret); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("the sign-in that used its guesses = %v, want it gone", err)
	}
	if _, err := f.Complete(t.Context(), in, "garbage that is no factor", browser); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("a factor after that = %v, want ErrNoSignIn", err)
	}
}

func TestOnlyAsManyGuessesAreJudgedAsTheSignInTakesWhenTheyComeAtOnce(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	in, _ := f.begin(t, "root")
	var wrong, gone, passed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 12 {
		wg.Go(func() {
			<-start
			_, err := f.Complete(t.Context(), in, "000000", browser)
			switch {
			case errors.Is(err, ErrBadFactor):
				wrong.Add(1)
			case errors.Is(err, ErrNoSignIn):
				gone.Add(1)
			case err == nil:
				passed.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if wrong.Load() != MaxGuesses || gone.Load() != 12-MaxGuesses || passed.Load() != 0 {
		t.Fatalf("%d guesses were judged, %d were turned down and %d passed, want %d, %d and none", wrong.Load(), gone.Load(), passed.Load(), MaxGuesses, 12-MaxGuesses)
	}
	if _, err := f.Complete(t.Context(), in, f.code(e.seed), browser); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("the right code afterwards = %v, want ErrNoSignIn", err)
	}
}

func TestTheSameCodeThatComesTwiceAtOnceOpensOneSession(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	in, _ := f.begin(t, "root")
	code := f.code(e.seed)
	var passed, refused atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range MaxGuesses {
		wg.Go(func() {
			<-start
			if _, err := f.Complete(t.Context(), in, code, browser); err == nil {
				passed.Add(1)
			} else if errors.Is(err, ErrBadFactor) || errors.Is(err, ErrNoSignIn) {
				refused.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if passed.Load() != 1 || refused.Load() != MaxGuesses-1 {
		t.Fatalf("%d requests with one code passed and %d were refused, want 1 and %d", passed.Load(), refused.Load(), MaxGuesses-1)
	}
	var logins int
	for _, r := range f.records(t) {
		if r.Action == audit.AdminLogin {
			logins++
		}
	}
	if logins != 2 {
		t.Fatalf("%d sign-ins were recorded, want the enrollment and one", logins)
	}
}

func TestARecoveryCodeSignsInOnceAndTheRestAreCounted(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	in, _ := f.begin(t, "root")
	typed := " " + strings.ToLower(e.codes[3]) + " "
	opened, err := f.Complete(t.Context(), in, typed, browser)
	if err != nil {
		t.Fatalf("Complete with a recovery code failed: %v", err)
	}
	if opened.Method != "password+recovery" || opened.RecoveryCodes != RecoveryCodeCount-1 {
		t.Fatalf("the session is %+v", opened)
	}
	used := f.record(t, audit.AdminRecoveryCodeUsed)
	if used.ActorID != e.account.ID || used.IP != browser.IP || !strings.Contains(used.Details, `"left":9`) || strings.Contains(used.Details, e.codes[3]) {
		t.Fatalf("the use of the code is recorded as %+v", used)
	}
	if !f.stored(t, "root").LastLoginAt.Equal(f.clock.read()) {
		t.Fatal("the time of the sign-in was not recorded")
	}
	again, _ := f.begin(t, "root")
	if _, err = f.Complete(t.Context(), again, e.codes[3], browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("the same recovery code again = %v, want ErrBadFactor", err)
	}
	if opened, err = f.Complete(t.Context(), again, e.codes[4], browser); err != nil || opened.RecoveryCodes != RecoveryCodeCount-2 {
		t.Fatalf("another recovery code = %+v, %v", opened, err)
	}
	other := f.enroll(t, "second")
	third, _ := f.begin(t, "second")
	if _, err = f.Complete(t.Context(), third, e.codes[5], browser); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("a recovery code of another administrator = %v, want ErrBadFactor", err)
	}
	if _, err = f.Complete(t.Context(), third, other.codes[0], browser); err != nil {
		t.Fatalf("a recovery code of the administrator = %v", err)
	}
}

func TestTheRecoveryCodesThatAreLeftAreCountedForTheAdministratorAlone(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	other := f.enroll(t, "second")
	for name, want := range map[string]int{e.account.ID: RecoveryCodeCount, other.account.ID: RecoveryCodeCount, "no-such-administrator": 0} {
		if left, err := f.RecoveryCodesLeft(t.Context(), name); err != nil || left != want {
			t.Fatalf("RecoveryCodesLeft(%q) = %d, %v, want %d", name, left, err, want)
		}
	}
	in, _ := f.begin(t, "root")
	if _, err := f.Complete(t.Context(), in, e.codes[0], browser); err != nil {
		t.Fatalf("Complete with a recovery code failed: %v", err)
	}
	if left, err := f.RecoveryCodesLeft(t.Context(), e.account.ID); err != nil || left != RecoveryCodeCount-1 {
		t.Fatalf("after one code was used there are %d, %v", left, err)
	}
	if left, err := f.RecoveryCodesLeft(t.Context(), other.account.ID); err != nil || left != RecoveryCodeCount {
		t.Fatalf("the codes of another administrator are %d, %v: they must not be counted together", left, err)
	}
}

func TestASignInThatWaitsIsNotValidAfterItsTimeOrAfterTheAccountChanged(t *testing.T) {
	f := newFixture(t)
	f.enroll(t, "root")
	_, waiting := f.begin(t, "root")
	f.clock.advance(PendingLifetime - time.Second)
	if _, err := f.Pending(t.Context(), waiting); err != nil {
		t.Fatalf("a sign-in a second before its end = %v", err)
	}
	f.clock.advance(time.Second)
	if _, err := f.Pending(t.Context(), waiting); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("a sign-in at its end = %v, want ErrNoSignIn", err)
	}
	if _, err := f.store.AdminSessions().ResolveBySecret(t.Context(), store.DefaultTenant, mustHash(t, waiting)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the sign-in that ended is still stored: %v", err)
	}

	for name, change := range map[string]func(g *fixture, t *testing.T){
		"a password that was reset": func(g *fixture, t *testing.T) {
			if err := g.ResetPassword(t.Context(), audit.CLI, "root", goodPassword+" again"); err != nil {
				t.Fatal(err)
			}
		},
		"an authenticator that was reset": func(g *fixture, t *testing.T) {
			if err := g.ResetTOTP(t.Context(), audit.CLI, "root"); err != nil {
				t.Fatal(err)
			}
		},
		"an account that was disabled": func(g *fixture, t *testing.T) {
			if err := g.Disable(t.Context(), audit.CLI, "root"); err != nil {
				t.Fatal(err)
			}
		},
		"an account that was deleted": func(g *fixture, t *testing.T) {
			if err := g.Delete(t.Context(), audit.CLI, "root"); err != nil {
				t.Fatal(err)
			}
		},
	} {
		g := newFixture(t)
		e := g.enroll(t, "root")
		changing, waiting := g.begin(t, "root")
		change(g, t)
		if _, err := g.Pending(t.Context(), waiting); !errors.Is(err, ErrNoSignIn) {
			t.Errorf("%s: Pending = %v, want ErrNoSignIn", name, err)
		}
		if _, err := g.Complete(t.Context(), changing, g.code(e.seed), browser); err == nil {
			t.Errorf("%s: the sign-in that waited went on", name)
		}
	}
}

func mustHash(t *testing.T, text string) []byte {
	t.Helper()
	hash, err := secret.Hash(text)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestASecretThatIsNotASecretOpensNothing(t *testing.T) {
	f := newFixture(t)
	f.enroll(t, "root")
	for _, text := range []string{"", "x", strings.Repeat("A", 43), strings.Repeat("A", 44), "!!!!", strings.Repeat("é", 43)} {
		if _, err := f.Pending(t.Context(), text); !errors.Is(err, ErrNoSignIn) {
			t.Errorf("Pending(%q) = %v, want ErrNoSignIn", text, err)
		}
		if _, err := f.Resolve(t.Context(), text); !errors.Is(err, ErrNoSession) {
			t.Errorf("Resolve(%q) = %v, want ErrNoSession", text, err)
		}
	}
}

func TestASessionEndsAtItsAbsoluteTimeAndWhenItIsIdle(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	secret := e.opened.Secret
	for range 24 {
		f.clock.advance(29 * time.Minute)
		if _, err := f.Resolve(t.Context(), secret); err != nil {
			t.Fatalf("a session that is used all the time = %v at %v", err, f.clock.read())
		}
	}
	f.clock.advance(29 * time.Minute)
	if _, err := f.Resolve(t.Context(), secret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("a session after its twelve hours = %v, want ErrNoSession", err)
	}
	if _, err := f.store.AdminSessions().ResolveBySecret(t.Context(), store.DefaultTenant, mustHash(t, secret)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the session that ended is still stored: %v", err)
	}

	g := newFixture(t)
	h := g.enroll(t, "root")
	g.clock.advance(30*time.Minute - 31*time.Second)
	if _, err := g.Resolve(t.Context(), h.opened.Secret); err != nil {
		t.Fatalf("a session a second before its idle time = %v", err)
	}
	g.clock.advance(30 * time.Minute)
	if _, err := g.Resolve(t.Context(), h.opened.Secret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("a session that was idle for thirty minutes = %v, want ErrNoSession", err)
	}
}

func TestTheUseOfASessionIsNotWrittenMoreOftenThanOnceAMinute(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	start := e.opened.LastSeenAt
	seen := func() time.Time {
		list, err := f.store.AdminSessions().ListByAdmin(t.Context(), store.DefaultTenant, e.account.ID, f.clock.read())
		if err != nil || len(list) != 1 {
			t.Fatalf("ListByAdmin = %v, %v", list, err)
		}
		return list[0].LastSeenAt
	}
	f.clock.advance(29 * time.Second)
	if _, err := f.Resolve(t.Context(), e.opened.Secret); err != nil || !seen().Equal(start) {
		t.Fatalf("a use after 59 seconds wrote the time: %v, %v", seen(), err)
	}
	f.clock.advance(time.Second)
	resolved, err := f.Resolve(t.Context(), e.opened.Secret)
	if err != nil || !seen().Equal(f.clock.read()) || !resolved.LastSeenAt.Equal(f.clock.read()) {
		t.Fatalf("a use after a minute did not write the time: %v, %v", seen(), err)
	}
}

func TestASessionEndsWhenItsAccountChangesOrIsDisabled(t *testing.T) {
	for name, change := range map[string]func(f *fixture, t *testing.T){
		"a changed account": func(f *fixture, t *testing.T) {
			a := f.stored(t, "root")
			a.PasswordHash += ""
			if _, err := f.store.Admins().Update(t.Context(), a); err != nil {
				t.Fatal(err)
			}
		},
		"a disabled account": func(f *fixture, t *testing.T) {
			a := f.stored(t, "root")
			a.Status = store.AdminDisabled
			if _, err := f.store.Admins().Update(t.Context(), a); err != nil {
				t.Fatal(err)
			}
		},
	} {
		f := newFixture(t)
		e := f.enroll(t, "root")
		if _, err := f.Resolve(t.Context(), e.opened.Secret); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		change(f, t)
		if _, err := f.Resolve(t.Context(), e.opened.Secret); !errors.Is(err, ErrNoSession) {
			t.Errorf("%s: Resolve = %v, want ErrNoSession", name, err)
		}
	}
}

func TestSigningOutEndsTheSessionAndIsRecordedOnce(t *testing.T) {
	f := newFixture(t)
	e := f.enroll(t, "root")
	if err := f.End(t.Context(), e.opened.Session, browser); err != nil {
		t.Fatalf("End failed: %v", err)
	}
	if _, err := f.Resolve(t.Context(), e.opened.Secret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the session that ended = %v", err)
	}
	record := f.record(t, audit.AdminLogout)
	if record.ActorID != e.account.ID || record.IP != browser.IP || !strings.Contains(record.Details, e.opened.ID) {
		t.Fatalf("the sign-out is recorded as %+v", record)
	}
	if err := f.End(t.Context(), e.opened.Session, browser); err != nil {
		t.Fatalf("End of a session that ended failed: %v", err)
	}
	f.record(t, audit.AdminLogout)
}

func TestWithoutTheSecondFactorThePasswordOpensASessionButOnlyWhereItIsAllowed(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	a, err := f.CheckPassword(t.Context(), "root", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if f.WithoutSecondFactor() {
		t.Fatal("the second factor is off by default")
	}
	if _, err = f.Open(t.Context(), a, browser); err == nil {
		t.Fatal("a session was opened without the second factor where it is not allowed")
	}
	f.noTOTP = true
	if _, err = f.Enroll(t.Context(), SignIn{Admin: a}); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("Enroll without the second factor = %v, want ErrNoSignIn", err)
	}
	opened, err := f.Open(t.Context(), a, browser)
	if err != nil || opened.Method != "password" {
		t.Fatalf("Open = %+v, %v", opened, err)
	}
	if _, err = f.Resolve(t.Context(), opened.Secret); err != nil {
		t.Fatalf("the session does not work: %v", err)
	}
	if !f.stored(t, "root").LastLoginAt.Equal(f.clock.read()) {
		t.Fatal("the sign-in was not recorded on the account")
	}
	if record := f.record(t, audit.AdminLogin); !strings.Contains(record.Details, `"method":"password"`) {
		t.Fatalf("the record is %+v", record)
	}
}

func TestAFailedSignInIsRecordedWithTheLoginOnlyOfAnAccountThatExists(t *testing.T) {
	f := newFixture(t)
	root := f.create(t, "root")
	if err := f.RecordFailure(t.Context(), browser, "  Root ", root.ID, "password", "wrong_password"); err != nil {
		t.Fatal(err)
	}
	if err := f.RecordFailure(t.Context(), browser, "hunter2 is my password", "", "password", "unknown_login"); err != nil {
		t.Fatal(err)
	}
	if err := f.RecordFailure(t.Context(), browser, "", "", "second_factor", "unknown_login"); err != nil {
		t.Fatal(err)
	}
	var failures []store.AuditRecord
	for _, r := range f.records(t) {
		if r.Action == audit.AdminLoginFailed {
			failures = append(failures, r)
		}
	}
	if len(failures) != 3 {
		t.Fatalf("%d failures were recorded, want 3", len(failures))
	}
	byLogin := map[string]store.AuditRecord{}
	for _, r := range failures {
		byLogin[r.Details] = r
	}
	known := byLogin[`{"login":"root","reason":"wrong_password","stage":"password"}`]
	unknown := byLogin[`{"login":"h***","reason":"unknown_login","stage":"password"}`]
	empty := byLogin[`{"login":"","reason":"unknown_login","stage":"second_factor"}`]
	if known.ActorID != root.ID || known.ActorKind != store.ActorAdmin || known.IP != browser.IP {
		t.Errorf("the failure on a known login is %+v", known)
	}
	if unknown.ActorID != "" || unknown.ActorKind != store.ActorAdmin || strings.Contains(unknown.Details, "hunter") {
		t.Errorf("the failure on an unknown login is %+v: the login is masked", unknown)
	}
	if empty.Details == "" {
		t.Errorf("the failure without a login is not recorded: %v", byLogin)
	}
}

func TestAnAgentOfAClientIsCleanedAndCut(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	a, err := f.CheckPassword(t.Context(), "root", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	agent := "Mozilla\x00/5.0\n\xff" + strings.Repeat("я", store.MaxUserAgentLength)
	pending, err := f.Begin(t.Context(), a, Client{IP: "203.0.113.9", UserAgent: agent})
	if err != nil {
		t.Fatalf("Begin with an agent that is long and dirty failed: %v", err)
	}
	in, err := f.Pending(t.Context(), pending.Secret)
	if err != nil {
		t.Fatal(err)
	}
	got := in.Session.UserAgent
	if !strings.HasPrefix(got, "Mozilla/5.0я") || len(got) > store.MaxUserAgentLength || strings.ContainsAny(got, "\x00\n") || strings.Contains(got, "\xff") || in.Session.IP != "203.0.113.9" {
		t.Fatalf("the agent is stored as %q", got)
	}
}

func TestTheErrorOfARefusedPasswordSaysWhyForTheLogAndIsTheSameErrorForTheCaller(t *testing.T) {
	f := newFixture(t)
	_, err := f.CheckPassword(t.Context(), "nobody", goodPassword)
	if !errors.Is(err, ErrBadCredentials) || !strings.Contains(err.Error(), "unknown_login") || !strings.Contains(err.Error(), "the login or the password is wrong") {
		t.Fatalf("the error is %q", err)
	}
	var refused *CredentialsError
	if !errors.As(err, &refused) || errors.Is(err, ErrNoSignIn) || errors.Is(&CredentialsError{Reason: "x"}, ErrNoSession) {
		t.Fatalf("the error is %#v", err)
	}
}

func TestASignInThatTheAdministratorLeavesIsEnded(t *testing.T) {
	f := newFixture(t)
	f.enroll(t, "root")
	in, secret := f.begin(t, "root")
	f.Abandon(t.Context(), in)
	if _, err := f.Pending(t.Context(), secret); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("Pending after Abandon = %v, want ErrNoSignIn", err)
	}
	f.Abandon(t.Context(), in)
}

type unusableHasher struct {
	Hasher
}

func (unusableHasher) Hash(context.Context, string) (string, error) {
	return "", errors.New("the hasher is out of memory")
}

func (h unusableHasher) Verify(ctx context.Context, password, encoded string) (bool, bool, error) {
	ok, _, err := h.Hasher.Verify(ctx, password, encoded)
	return ok, true, err
}

type staleOnUpdate struct {
	store.Admins
	changed func()
}

func (s staleOnUpdate) Update(_ context.Context, _ store.Admin) (store.Admin, error) {
	s.changed()
	return store.Admin{}, store.ErrStale
}

type staleOnUpdateStore struct {
	store.Store
	changed func()
}

func (s staleOnUpdateStore) Admins() store.Admins {
	return staleOnUpdate{Admins: s.Store.Admins(), changed: s.changed}
}

func TestAHashThatCannotBeMadeAgainDoesNotStopTheSignIn(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	before := f.stored(t, "root")
	f.hasher = unusableHasher{Hasher: f.hasher}
	a, err := f.CheckPassword(t.Context(), "root", goodPassword)
	if err != nil || a.Version != before.Version || a.PasswordHash != before.PasswordHash {
		t.Fatalf("CheckPassword = %+v, %v: the sign-in goes on with the account as it was", a, err)
	}

	g := newFixture(t)
	g.create(t, "root")
	g.hasher = &countingHasher{Hasher: g.hasher, rehash: true}
	bumped := false
	g.Service.store = staleOnUpdateStore{Store: g.store, changed: func() {
		if bumped {
			return
		}
		bumped = true
		current := g.stored(t, "root")
		if _, updateErr := g.store.Admins().Update(t.Context(), current); updateErr != nil {
			t.Error(updateErr)
		}
	}}
	a, err = g.CheckPassword(t.Context(), "root", goodPassword)
	if err != nil || a.Version != 2 {
		t.Fatalf("CheckPassword after another change = %+v, %v, want the account as it is now", a, err)
	}
}

func TestASignInIsNotBegunForAnAccountThatIsGone(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	a, err := f.CheckPassword(t.Context(), "root", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Delete(t.Context(), audit.CLI, "root"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Begin(t.Context(), a, browser); !errors.Is(err, ErrNoSignIn) {
		t.Fatalf("Begin for an account that was deleted = %v, want ErrNoSignIn", err)
	}
}

func TestALoginThatIsNotTextIsMaskedWithoutItsFirstCharacter(t *testing.T) {
	f := newFixture(t)
	if err := f.RecordFailure(t.Context(), browser, "\xff\xfe", "", "password", "invalid_login"); err != nil {
		t.Fatal(err)
	}
	if err := f.RecordFailure(t.Context(), browser, "  я-хакер  ", "", "password", "invalid_login"); err != nil {
		t.Fatal(err)
	}
	var shown []string
	for _, r := range f.records(t) {
		shown = append(shown, r.Details)
	}
	if len(shown) != 2 || !strings.Contains(strings.Join(shown, " "), `"login":"***"`) || !strings.Contains(strings.Join(shown, " "), `"login":"я***"`) {
		t.Fatalf("the records are %v", shown)
	}
}
