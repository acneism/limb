package admin

import (
	"bytes"
	"encoding/base32"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/internal/audit"
	"github.com/acneism/limb/internal/secret"
	"github.com/acneism/limb/internal/totp"
	"github.com/acneism/limb/store"
)

func boundAdmin(t *testing.T, f *fixture, login string) (store.Admin, Enrollment) {
	t.Helper()
	f.create(t, login)
	a := f.stored(t, login)
	enrollment, err := f.NewEnrollment(a)
	if err != nil {
		t.Fatalf("NewEnrollment failed: %v", err)
	}
	a.TOTPSecret = enrollment.Sealed
	a.TOTPConfirmedAt = f.clock.read()
	updated, err := f.store.Admins().Update(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	return updated, enrollment
}

func TestAnEnrollmentCarriesAFreshSealedSeed(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	a := f.stored(t, "root")
	first, err := f.NewEnrollment(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.NewEnrollment(a)
	if err != nil || bytes.Equal(first.Seed, second.Seed) || bytes.Equal(first.Sealed, second.Sealed) {
		t.Fatalf("two enrollments are alike: %v", err)
	}
	if len(first.Seed) != totp.SecretLength {
		t.Fatalf("the seed has %d bytes, want %d", len(first.Seed), totp.SecretLength)
	}
	opened, err := f.keys.OpenTOTP(first.Sealed, a.ID)
	if err != nil || !bytes.Equal(opened, first.Seed) {
		t.Fatalf("the sealed seed does not open for the administrator: %v", err)
	}
	if _, err = f.keys.OpenTOTP(first.Sealed, "another-admin"); err == nil {
		t.Fatal("the sealed seed opens for another administrator")
	}
	if bytes.Contains(first.Sealed, first.Seed) {
		t.Fatal("the sealed seed holds the seed as it is")
	}
	if text, decodeErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(first.Secret); decodeErr != nil || !bytes.Equal(text, first.Seed) {
		t.Fatalf("the typed secret is not the seed in base32: %v", decodeErr)
	}
	parsed, err := url.Parse(first.URI)
	if err != nil || parsed.Scheme != "otpauth" || parsed.Path != "/Acme:root" || parsed.Query().Get("secret") != first.Secret || parsed.Query().Get("issuer") != "Acme" {
		t.Fatalf("the address is %s, %v", first.URI, err)
	}
}

func TestAnEnrollmentThatWasShownIsShownAgainAsItWas(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	a := f.stored(t, "root")
	made, err := f.NewEnrollment(a)
	if err != nil {
		t.Fatal(err)
	}
	a.TOTPSecret = made.Sealed
	again, err := f.OpenEnrollment(a)
	if err != nil || !bytes.Equal(again.Seed, made.Seed) || again.Secret != made.Secret || again.URI != made.URI || !bytes.Equal(again.Sealed, made.Sealed) {
		t.Fatalf("OpenEnrollment = %+v, %v; want what NewEnrollment made", again, err)
	}
	damaged := a
	damaged.TOTPSecret = bytes.Clone(made.Sealed)
	damaged.TOTPSecret[len(damaged.TOTPSecret)-1] ^= 1
	if _, err = f.OpenEnrollment(damaged); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("OpenEnrollment of a damaged seed = %v, want ErrOpen", err)
	}
	copied := a
	copied.ID = "another-admin"
	if _, err = f.OpenEnrollment(copied); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("OpenEnrollment of a seed that was copied to another administrator = %v, want ErrOpen", err)
	}
	if _, err = f.OpenEnrollment(store.Admin{ID: a.ID}); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("OpenEnrollment without a seed = %v, want ErrOpen", err)
	}
}

func TestTheRecoveryCodesAreTenAndTheirHashesBelongToTheAdministrator(t *testing.T) {
	f := newFixture(t)
	shown, hashes, err := f.NewRecoveryCodes("admin-1")
	if err != nil || len(shown) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount || RecoveryCodeCount != 10 {
		t.Fatalf("NewRecoveryCodes = %d codes, %d hashes, %v; want 10 of each", len(shown), len(hashes), err)
	}
	form := regexp.MustCompile(`^[A-Z2-7]{5}(-[A-Z2-7]{5}){4}$`)
	seen := map[string]bool{}
	for i, code := range shown {
		if !form.MatchString(code) || seen[code] {
			t.Fatalf("the code %q is not in groups of five or was made twice", code)
		}
		seen[code] = true
		canonical, ok := secret.ParseRecoveryCode(code)
		if !ok || !bytes.Equal(f.keys.RecoveryHash("admin-1", canonical), hashes[i]) {
			t.Fatalf("the hash %d is not the hash of the code %q for the administrator", i, code)
		}
		if bytes.Equal(f.keys.RecoveryHash("admin-2", canonical), hashes[i]) {
			t.Fatalf("the hash %d is the same for another administrator", i)
		}
		for j := range i {
			if bytes.Equal(hashes[i], hashes[j]) {
				t.Fatalf("the hashes %d and %d are the same", i, j)
			}
		}
	}
}

func TestAOneTimePasswordIsReadAtTheMomentItIsGiven(t *testing.T) {
	f := newFixture(t)
	a, enrollment := boundAdmin(t, f, "root")
	now := f.clock.read()
	step := totp.Step(now)
	for name, input := range map[string]string{
		"the current password": totp.Code(enrollment.Seed, step),
		"with a space":         totp.Code(enrollment.Seed, step)[:3] + " " + totp.Code(enrollment.Seed, step)[3:],
	} {
		got, err := f.ReadFactor(a, input, now)
		if err != nil || got.Kind != FactorTOTP || got.Step != step || got.Hash != nil {
			t.Errorf("%s: ReadFactor = %+v, %v; want the password of the step %d", name, got, err, step)
		}
	}
	for delta := int64(-1); delta <= 1; delta++ {
		got, err := f.ReadFactor(a, totp.Code(enrollment.Seed, step+delta), now)
		if err != nil || got.Step != step+delta {
			t.Errorf("the password of the step %+d: ReadFactor = %+v, %v", delta, got, err)
		}
	}
	for _, delta := range []int64{-2, 2, 10} {
		if _, err := f.ReadFactor(a, totp.Code(enrollment.Seed, step+delta), now); !errors.Is(err, ErrBadFactor) {
			t.Errorf("the password of the step %+d = %v, want ErrBadFactor", delta, err)
		}
	}
	right := totp.Code(enrollment.Seed, step)
	wrong := right[:5] + string(rune('0'+(right[5]-'0'+1)%10))
	if _, err := f.ReadFactor(a, wrong, now); !errors.Is(err, ErrBadFactor) {
		t.Errorf("a wrong password = %v, want ErrBadFactor", err)
	}
	other, _ := boundAdmin(t, f, "second")
	if _, err := f.ReadFactor(other, right, now); !errors.Is(err, ErrBadFactor) {
		t.Errorf("the password of another administrator = %v, want ErrBadFactor", err)
	}
}

func TestAOneTimePasswordCanBeUsedOnceWhateverTheClockOfTheStore(t *testing.T) {
	f := newFixture(t)
	a, enrollment := boundAdmin(t, f, "root")
	now := f.clock.read()
	read := func() Factor {
		got, err := f.ReadFactor(a, totp.Code(enrollment.Seed, totp.Step(now)), now)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	first := read()
	if err := f.store.Admins().AcceptStep(t.Context(), a.TenantID, a.ID, a.Version, first.Step, now); err != nil {
		t.Fatalf("AcceptStep failed: %v", err)
	}
	if again := read(); again.Step != first.Step {
		t.Fatalf("the same password is read as another step: %d and %d", first.Step, again.Step)
	}
	if err := f.store.Admins().AcceptStep(t.Context(), a.TenantID, a.ID, a.Version, read().Step, now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a password that was used = %v, want ErrConflict", err)
	}
}

func TestARecoveryCodeIsReadAndHashedForTheStoreToCheck(t *testing.T) {
	f := newFixture(t)
	a, _ := boundAdmin(t, f, "root")
	shown, hashes, err := f.NewRecoveryCodes(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.Admins().ReplaceRecoveryCodes(t.Context(), a.TenantID, a.ID, hashes); err != nil {
		t.Fatal(err)
	}
	now := f.clock.read()
	for _, input := range []string{shown[0], strings.ToLower(shown[0]), " " + strings.ReplaceAll(shown[0], "-", " ") + " "} {
		got, readErr := f.ReadFactor(a, input, now)
		if readErr != nil || got.Kind != FactorRecovery || got.Step != 0 || !bytes.Equal(got.Hash, hashes[0]) {
			t.Fatalf("ReadFactor(%q) = %+v, %v; want the recovery code 0", input, got, readErr)
		}
	}
	got, err := f.ReadFactor(a, shown[3], now)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.Admins().UseRecoveryCode(t.Context(), a.TenantID, a.ID, got.Hash, now); err != nil {
		t.Fatalf("UseRecoveryCode of a code that was read failed: %v", err)
	}
	if err = f.store.Admins().UseRecoveryCode(t.Context(), a.TenantID, a.ID, got.Hash, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a recovery code used twice = %v, want ErrNotFound", err)
	}
	strange, err := f.ReadFactor(a, "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY", now)
	if err != nil || strange.Kind != FactorRecovery {
		t.Fatalf("a code in the right form is read, and the store tells it is not there: %+v, %v", strange, err)
	}
	if err = f.store.Admins().UseRecoveryCode(t.Context(), a.TenantID, a.ID, strange.Hash, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a recovery code that was never given = %v, want ErrNotFound", err)
	}
}

func TestWhatIsNeitherAPasswordNorACodeIsRefused(t *testing.T) {
	f := newFixture(t)
	a, _ := boundAdmin(t, f, "root")
	now := f.clock.read()
	for _, input := range []string{"", " ", "12345", "1234567", "abcdef", "ABCDE-FGHIJ", "ABCDE-FGHIJ-KLMNO-PQRST-UVWX0", "١٢٣٤٥٦", "123456\n654321", strings.Repeat("A", 500)} {
		if got, err := f.ReadFactor(a, input, now); !errors.Is(err, ErrBadFactor) || got.Kind != "" || got.Step != 0 || got.Hash != nil {
			t.Errorf("ReadFactor(%q) = %+v, %v; want ErrBadFactor", input, got, err)
		}
	}
}

func TestAnAdministratorWithoutASeedHasNoSecondFactor(t *testing.T) {
	f := newFixture(t)
	f.create(t, "root")
	a := f.stored(t, "root")
	now := f.clock.read()
	for _, input := range []string{"123456", "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY", ""} {
		if _, err := f.ReadFactor(a, input, now); !errors.Is(err, ErrBadFactor) {
			t.Errorf("ReadFactor(%q) of an administrator without a seed = %v, want ErrBadFactor", input, err)
		}
	}
}

func TestASeedThatCannotBeOpenedIsNotAWrongPassword(t *testing.T) {
	f := newFixture(t)
	a, enrollment := boundAdmin(t, f, "root")
	now := f.clock.read()
	code := totp.Code(enrollment.Seed, totp.Step(now))
	damaged := a
	damaged.TOTPSecret = bytes.Clone(a.TOTPSecret)
	damaged.TOTPSecret[5] ^= 1
	if _, err := f.ReadFactor(damaged, code, now); err == nil || errors.Is(err, ErrBadFactor) || !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("ReadFactor with a damaged seed = %v, want the failure to open it", err)
	}
	copied := a
	copied.ID = "another-admin"
	if _, err := f.ReadFactor(copied, code, now); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("ReadFactor with a seed that belongs to another administrator = %v, want the failure to open it", err)
	}
}

func TestTheFactorsOfAdministratorsDoNotWorkForOthers(t *testing.T) {
	f := newFixture(t)
	root, rootSeed := boundAdmin(t, f, "root")
	second, _ := boundAdmin(t, f, "second")
	_, hashes, err := f.NewRecoveryCodes(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.Admins().ReplaceRecoveryCodes(t.Context(), root.TenantID, root.ID, hashes); err != nil {
		t.Fatal(err)
	}
	shown, _, err := f.NewRecoveryCodes(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.ReadFactor(second, shown[0], f.clock.read())
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.Admins().UseRecoveryCode(t.Context(), second.TenantID, second.ID, got.Hash, f.clock.read()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a recovery code of one administrator works for another: %v", err)
	}
	if _, err = f.ReadFactor(second, totp.Code(rootSeed.Seed, totp.Step(f.clock.read())), f.clock.read()); !errors.Is(err, ErrBadFactor) {
		t.Fatalf("a password of one administrator works for another: %v", err)
	}
	f.clock.advance(time.Hour)
	if err = f.ResetTOTP(t.Context(), audit.CLI, "second"); err != nil {
		t.Fatal(err)
	}
}
