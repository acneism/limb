package limb

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

type fixture struct {
	a        *Auth
	counting *countingHasher
	user     User
}

func newFixture(t *testing.T, opts ...Option) *fixture {
	t.Helper()
	a := newTestAuth(t, append([]Option{emailAndUsername()}, opts...)...)
	user := mustRegister(t, a, map[string]string{"email": "Nina@Example.com", "username": "nina_n"}, goodPassword)
	counting := &countingHasher{passwordHasher: a.hasher}
	a.hasher = counting
	return &fixture{a: a, counting: counting, user: user}
}

func (f *fixture) stored(t *testing.T) store.User {
	t.Helper()
	u, err := f.a.store.Users().Get(t.Context(), store.DefaultTenant, string(f.user.ID))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *fixture) change(t *testing.T, edit func(*store.User)) {
	t.Helper()
	u := f.stored(t)
	edit(&u)
	if _, err := f.a.store.Users().Update(t.Context(), u); err != nil {
		t.Fatal(err)
	}
}

func TestCheckPasswordAcceptsEveryLoginForm(t *testing.T) {
	f := newFixture(t)
	logins := []string{"nina@example.com", "  NINA@EXAMPLE.COM ", "Nina@Example.com", "Nina_N", " nina_n ", "NINA_N"}
	for _, login := range logins {
		user, found, err := f.a.checkPassword(t.Context(), login, goodPassword)
		if err != nil {
			t.Fatalf("checkPassword(%q) failed: %v", login, err)
		}
		if string(f.user.ID) != user.ID || found.UserID != user.ID || user.PasswordHash == "" || user.Version != 1 {
			t.Fatalf("checkPassword(%q) = %+v %+v", login, user, found)
		}
	}
	if got := f.counting.verifies.Load(); int(got) != len(logins) || f.counting.dummies.Load() != 0 || f.counting.hashes.Load() != 0 {
		t.Fatalf("verifies=%d dummies=%d hashes=%d", got, f.counting.dummies.Load(), f.counting.hashes.Load())
	}
}

func TestCheckPasswordRejectsWithTheSameError(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name     string
		login    string
		password string
		verifies int32
		dummies  int32
	}{
		{"wrong password for an e-mail address", "nina@example.com", "not the password", 1, 0},
		{"wrong password for a nickname", "nina_n", "not the password", 1, 0},
		{"empty password", "nina@example.com", "", 1, 0},
		{"unknown e-mail address", "ghost@example.com", goodPassword, 0, 1},
		{"unknown nickname", "ghost_g", goodPassword, 0, 1},
		{"login in no known form", "+79261234567", goodPassword, 0, 1},
		{"empty login", "", goodPassword, 0, 1},
		{"blank login", "   ", goodPassword, 0, 1},
		{"login with spaces", "not a login at all", goodPassword, 0, 1},
		{"huge login", strings.Repeat("a", 5000), goodPassword, 0, 1},
		{"huge password", "nina@example.com", strings.Repeat("p", 5000), 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.counting.verifies.Store(0)
			f.counting.dummies.Store(0)
			user, found, err := f.a.checkPassword(t.Context(), tc.login, tc.password)
			if err != ErrInvalidCredentials { //nolint:errorlint
				t.Fatalf("err = %v, want exactly ErrInvalidCredentials", err)
			}
			if user.ID != "" || found.Value != "" {
				t.Fatalf("a failed check must not return data: %+v %+v", user, found)
			}
			if f.counting.verifies.Load() != tc.verifies || f.counting.dummies.Load() != tc.dummies {
				t.Fatalf("verifies=%d dummies=%d, want %d and %d: an unknown login must cost the same hash computation as a wrong password",
					f.counting.verifies.Load(), f.counting.dummies.Load(), tc.verifies, tc.dummies)
			}
		})
	}
}

func TestCheckPasswordHonoursTheStateOfTheAccount(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		status store.Status
		until  time.Time
		want   error
	}{
		{"active", store.StatusActive, time.Time{}, nil},
		{"blocked without an end", store.StatusBlocked, time.Time{}, ErrUserBlocked},
		{"blocked until the future", store.StatusBlocked, base.Add(time.Hour), ErrUserBlocked},
		{"block that has ended", store.StatusBlocked, base.Add(-time.Hour), nil},
		{"block that ends right now", store.StatusBlocked, base, nil},
		{"deleted", store.StatusDeleted, time.Time{}, ErrInvalidCredentials},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.a.now = func() time.Time { return base }
			f.change(t, func(u *store.User) {
				u.Status = tc.status
				u.BlockedUntil = tc.until
				if tc.status == store.StatusBlocked {
					u.BlockedReason = "abuse"
				}
			})
			_, _, err := f.a.checkPassword(t.Context(), "nina@example.com", goodPassword)
			if !errors.Is(err, tc.want) {
				t.Fatalf("with the right password: %v, want %v", err, tc.want)
			}
			_, _, err = f.a.checkPassword(t.Context(), "nina@example.com", "the wrong password")
			if err != ErrInvalidCredentials { //nolint:errorlint
				t.Fatalf("with a wrong password the answer must always be ErrInvalidCredentials, got %v", err)
			}
		})
	}
}

func TestCheckPasswordWithoutAPassword(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	invited := store.User{TenantID: store.DefaultTenant, ID: "00000000-0000-7000-8000-0000000000aa", Status: store.StatusActive, CreatedAt: time.Now()}
	if err := f.a.store.Users().Create(ctx, invited); err != nil {
		t.Fatal(err)
	}
	if err := f.a.store.Identifiers().Add(ctx, store.Identifier{TenantID: store.DefaultTenant, Type: "email", Value: "invited@example.com", DisplayValue: "invited@example.com", UserID: invited.ID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.a.checkPassword(ctx, "invited@example.com", goodPassword); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if f.counting.dummies.Load() != 1 || f.counting.verifies.Load() != 0 {
		t.Fatalf("an account without a password must cost a dummy verification: dummies=%d verifies=%d", f.counting.dummies.Load(), f.counting.verifies.Load())
	}
}

func TestCheckPasswordWithAnUnusableHash(t *testing.T) {
	logger, logs := capturingLogger()
	f := newFixture(t, WithLogger(logger))
	f.change(t, func(u *store.User) { u.PasswordHash = "garbage-hash-value" })
	if _, _, err := f.a.checkPassword(t.Context(), "nina@example.com", goodPassword); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("err = %v, want ErrInvalidCredentials: a damaged hash must look like a wrong password", err)
	}
	if f.counting.dummies.Load() != 1 {
		t.Fatalf("a damaged hash must cost a dummy verification, got %d", f.counting.dummies.Load())
	}
	text := logs.String()
	if !strings.Contains(text, "cannot be used") || !strings.Contains(text, string(f.user.ID)) {
		t.Fatalf("the problem must be logged with the user ID:\n%s", text)
	}
	if strings.Contains(text, "garbage-hash-value") || strings.Contains(text, goodPassword) {
		t.Fatalf("logs must not contain hashes or passwords:\n%s", text)
	}
}

func TestCheckPasswordUpgradesOutdatedHashes(t *testing.T) {
	f := newFixture(t)
	before := f.stored(t)
	if !strings.Contains(before.PasswordHash, "m=64,t=1,p=1") {
		t.Fatalf("the fixture must start with weak parameters: %s", before.PasswordHash)
	}
	f.counting.passwordHasher = newHasher(t, strongParams)

	user, _, err := f.a.checkPassword(t.Context(), "nina_n", goodPassword)
	if err != nil {
		t.Fatalf("checkPassword failed: %v", err)
	}
	after := f.stored(t)
	if !strings.Contains(after.PasswordHash, "m=128,t=2,p=1") || after.Version != before.Version+1 {
		t.Fatalf("the hash must be recomputed with the current parameters: %s at version %d", after.PasswordHash, after.Version)
	}
	if user.PasswordHash != after.PasswordHash || user.Version != after.Version {
		t.Fatalf("the returned user must be the upgraded one: %+v", user)
	}
	if ok, _, verifyErr := f.counting.passwordHasher.Verify(t.Context(), goodPassword, after.PasswordHash); verifyErr != nil || !ok {
		t.Fatalf("the new hash must match the password: %v %v", ok, verifyErr)
	}
	if _, _, err = f.a.checkPassword(t.Context(), "nina_n", goodPassword); err != nil {
		t.Fatal(err)
	}
	if f.counting.hashes.Load() != 1 || f.stored(t).Version != after.Version {
		t.Fatalf("a current hash must not be recomputed again: %d hashes", f.counting.hashes.Load())
	}
}

func TestCheckPasswordDoesNotUpgradeOnFailure(t *testing.T) {
	f := newFixture(t)
	f.counting.passwordHasher = newHasher(t, strongParams)
	before := f.stored(t)
	if _, _, err := f.a.checkPassword(t.Context(), "nina_n", "wrong password"); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatal(err)
	}
	f.change(t, func(u *store.User) { u.Status = store.StatusBlocked })
	changed := f.stored(t)
	if _, _, err := f.a.checkPassword(t.Context(), "nina_n", goodPassword); !errors.Is(err, ErrUserBlocked) {
		t.Fatal(err)
	}
	if f.counting.hashes.Load() != 0 || f.stored(t).PasswordHash != before.PasswordHash || f.stored(t).Version != changed.Version {
		t.Fatalf("only a successful sign-in may upgrade the hash: %d hashes", f.counting.hashes.Load())
	}
}

func TestCheckPasswordDoesNotRevertAConcurrentPasswordChange(t *testing.T) {
	logger, logs := capturingLogger()
	f := newFixture(t, WithLogger(logger))
	f.counting.passwordHasher = newHasher(t, strongParams)
	const newPassword = "a brand new password!"
	changedHash, err := newHasher(t, weakParams).Hash(t.Context(), newPassword)
	if err != nil {
		t.Fatal(err)
	}
	f.a.store = &faultyStore{Store: f.a.store, beforeSave: func(ctx context.Context, users store.Users, u store.User) {
		current, getErr := users.Get(ctx, store.DefaultTenant, u.ID)
		if getErr != nil {
			t.Error(getErr)
			return
		}
		current.PasswordHash = changedHash
		if _, updateErr := users.Update(ctx, current); updateErr != nil {
			t.Error(updateErr)
		}
	}}
	if _, _, err = f.a.checkPassword(t.Context(), "nina_n", goodPassword); err != nil {
		t.Fatalf("a concurrent change must not fail the sign-in: %v", err)
	}
	if got := f.stored(t).PasswordHash; got != changedHash {
		t.Fatalf("the new password was reverted by the upgrade of the old one: %s", got)
	}
	if strings.Contains(logs.String(), "level=WARN") || strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("a concurrent change is expected and must not be a warning:\n%s", logs.String())
	}
}

func TestCheckPasswordSurvivesFailedUpgrades(t *testing.T) {
	boom := errors.New("disk is full")
	for name, prepare := range map[string]func(*fixture){
		"hashing fails":   func(f *fixture) { f.counting.hashErr = boom },
		"the store fails": func(f *fixture) { f.a.store = &faultyStore{Store: f.a.store, updateErr: boom} },
	} {
		t.Run(name, func(t *testing.T) {
			logger, logs := capturingLogger()
			f := newFixture(t, WithLogger(logger))
			f.counting.passwordHasher = newHasher(t, strongParams)
			before := f.stored(t)
			prepare(f)
			user, _, err := f.a.checkPassword(t.Context(), "nina_n", goodPassword)
			if err != nil || user.ID != before.ID {
				t.Fatalf("a failed upgrade must not fail the sign-in: %v", err)
			}
			if f.stored(t).PasswordHash != before.PasswordHash {
				t.Fatal("the old hash must stay when the upgrade fails")
			}
			if !strings.Contains(logs.String(), "level=WARN") || strings.Contains(logs.String(), goodPassword) {
				t.Fatalf("the failure must be logged as a warning without secrets:\n%s", logs.String())
			}
		})
	}
}

func TestCheckPasswordReportsInfrastructureErrors(t *testing.T) {
	boom := errors.New("database is down")
	cases := map[string]func(*fixture){
		"finding the identifier fails": func(f *fixture) { f.a.store = &faultyStore{Store: f.a.store, findErr: boom} },
		"reading the user fails":       func(f *fixture) { f.a.store = &faultyStore{Store: f.a.store, getErr: boom} },
		"verifying fails with a deadline": func(f *fixture) {
			f.counting.verifyErr = context.DeadlineExceeded
			boom = context.DeadlineExceeded
		},
		"the dummy verification is canceled": func(f *fixture) {
			f.counting.dummyErr = context.Canceled
			boom = context.Canceled
		},
	}
	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			prepare(f)
			login := "nina@example.com"
			if strings.Contains(name, "dummy") {
				login = "ghost@example.com"
			}
			_, _, err := f.a.checkPassword(t.Context(), login, goodPassword)
			if !errors.Is(err, boom) || errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err = %v, want %v and not ErrInvalidCredentials: an outage is not a wrong password", err, boom)
			}
		})
	}
}

func TestCheckPasswordWithACanceledContext(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := f.a.checkPassword(ctx, "nina@example.com", goodPassword)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestCheckPasswordIgnoresOtherTenants(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	hash, err := f.counting.passwordHasher.Hash(ctx, goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	stranger := store.User{TenantID: otherTenant, ID: "00000000-0000-7000-8000-0000000000bb", Status: store.StatusActive, PasswordHash: hash, CreatedAt: time.Now()}
	if err = f.a.store.Users().Create(ctx, stranger); err != nil {
		t.Fatal(err)
	}
	if err = f.a.store.Identifiers().Add(ctx, store.Identifier{TenantID: otherTenant, Type: "email", Value: "stranger@example.com", DisplayValue: "stranger@example.com", UserID: stranger.ID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.a.checkPassword(ctx, "stranger@example.com", goodPassword); err != ErrInvalidCredentials { //nolint:errorlint
		t.Fatalf("a user of another tenant must not be found, got %v", err)
	}
}

func TestCheckPasswordNeverLogsSecrets(t *testing.T) {
	logger, logs := capturingLogger()
	f := newFixture(t, WithLogger(logger))
	f.counting.passwordHasher = newHasher(t, strongParams)
	for _, attempt := range []struct{ login, password string }{
		{"nina@example.com", goodPassword}, {"nina@example.com", "wrong password!"}, {"ghost@example.com", goodPassword},
	} {
		_, _, _ = f.a.checkPassword(t.Context(), attempt.login, attempt.password)
	}
	for _, secret := range []string{goodPassword, "wrong password!", "$argon2id$"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("logs must not contain %q:\n%s", secret, logs.String())
		}
	}
}
