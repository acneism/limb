package limb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/store"
)

func TestRegister(t *testing.T) {
	a := newTestAuth(t, emailAndUsername())
	moment := time.Date(2026, 5, 6, 7, 8, 9, 123456789, time.FixedZone("UTC+3", 3*60*60))
	a.now = func() time.Time { return moment }

	user, err := a.Register(t.Context(), Registration{
		Identifiers: map[string]string{"email": "  Alice@Example.COM ", "username": "Alice_W"},
		Password:    goodPassword,
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	parsed, err := uuid.Parse(string(user.ID))
	if err != nil || parsed.Version() != 7 || len(user.ID) != 36 {
		t.Fatalf("the ID %q must be a UUIDv7 in text form: %v", user.ID, err)
	}
	if user.Status != StatusActive || user.MustChangePassword || !user.LastLoginAt.IsZero() {
		t.Fatalf("unexpected state: %+v", user)
	}
	if want := time.Date(2026, 5, 6, 4, 8, 9, 123456000, time.UTC); !user.CreatedAt.Equal(want) || user.CreatedAt.Location() != time.UTC {
		t.Fatalf("CreatedAt = %v, want %v in UTC cut to microseconds", user.CreatedAt, want)
	}
	want := []UserIdentifier{
		{Type: "email", Value: "alice@example.com", DisplayValue: "Alice@Example.COM"},
		{Type: "username", Value: "alice_w", DisplayValue: "Alice_W"},
	}
	if len(user.Identifiers) != len(want) {
		t.Fatalf("Identifiers = %+v, want %+v", user.Identifiers, want)
	}
	for n := range want {
		if user.Identifiers[n] != want[n] {
			t.Fatalf("Identifiers[%d] = %+v, want %+v", n, user.Identifiers[n], want[n])
		}
	}

	stored, err := a.store.Users().Get(t.Context(), store.DefaultTenant, string(user.ID))
	if err != nil {
		t.Fatalf("the user was not stored: %v", err)
	}
	if stored.Version != 1 || stored.Status != store.StatusActive || !strings.HasPrefix(stored.PasswordHash, "$argon2id$v=19$") || strings.Contains(stored.PasswordHash, goodPassword) {
		t.Fatalf("unexpected stored user: %+v", stored)
	}
	if ok, _, err := a.hasher.Verify(t.Context(), goodPassword, stored.PasswordHash); err != nil || !ok {
		t.Fatalf("the stored hash must match the password: %v %v", ok, err)
	}
	for _, i := range want {
		found, err := a.store.Identifiers().Find(t.Context(), store.DefaultTenant, i.Type, i.Value)
		if err != nil || found.UserID != string(user.ID) || found.DisplayValue != i.DisplayValue || !found.VerifiedAt.IsZero() {
			t.Fatalf("the %s identifier was not stored as expected: %+v, %v", i.Type, found, err)
		}
	}
}

func TestRegisterBlankOptionalValuesAreMissing(t *testing.T) {
	a := newTestAuth(t, emailAndUsername())
	user := mustRegister(t, a, map[string]string{"email": "bob@example.com", "username": "   "}, goodPassword)
	if len(user.Identifiers) != 1 || user.Identifiers[0].Type != "email" {
		t.Fatalf("a blank optional value must be left out: %+v", user.Identifiers)
	}
}

func TestRegisterValidation(t *testing.T) {
	a := newTestAuth(t, WithIdentifiers(
		identifier.Email(),
		identifier.Username(),
		identifier.Custom("badge", identifier.Pattern(`[0-9]{4}`), identifier.Required()),
		identifier.Custom("pager", identifier.Delivery()),
	))
	cases := []struct {
		name   string
		fields map[string]string
		field  string
		reason string
	}{
		{"unknown type", map[string]string{"email": "a@example.com", "badge": "1234", "phone": "+79261234567"}, "phone", "unknown identifier type"},
		{"unknown type with a blank value", map[string]string{"badge": "1234", "email": "a@example.com", "fax": ""}, "fax", "unknown identifier type"},
		{"required value missing", map[string]string{"email": "a@example.com"}, "badge", "required"},
		{"required value blank", map[string]string{"email": "a@example.com", "badge": " \t"}, "badge", "required"},
		{"invalid e-mail", map[string]string{"email": "not an address", "badge": "1234"}, "email", "invalid e-mail address"},
		{"invalid nickname", map[string]string{"username": "ab", "badge": "1234"}, "username", "value is too short: at least 3 characters required"},
		{"invalid custom value", map[string]string{"email": "a@example.com", "badge": "12"}, "badge", "value has an invalid format"},
		{"nothing to sign in with", map[string]string{"badge": "1234", "pager": "555"}, "identifiers", "at least one value to sign in with is required"},
		{"no values at all", nil, "badge", "required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.Register(t.Context(), Registration{Identifiers: tc.fields, Password: goodPassword})
			var invalid *ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("Register = %v, want a *ValidationError", err)
			}
			if invalid.Field != tc.field || invalid.Reason != tc.reason {
				t.Fatalf("got field %q reason %q, want field %q reason %q", invalid.Field, invalid.Reason, tc.field, tc.reason)
			}
			if !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("the error text %q must show the field and the reason", err)
			}
		})
	}
}

func TestRegisterPolicy(t *testing.T) {
	a := newTestAuth(t, emailAndUsername(), WithPasswordPolicy(PasswordPolicy{
		Checks: []func(context.Context, string) error{func(_ context.Context, pw string) error {
			if strings.Contains(pw, "leaked") {
				return errors.New("breached")
			}
			return nil
		}},
	}))
	fields := map[string]string{"email": "carol@example.com", "username": "carol_c"}
	cases := []struct {
		name     string
		password string
		want     []string
	}{
		{"empty", "", []string{"min_length"}},
		{"too short", "short-1", []string{"min_length"}},
		{"too long", strings.Repeat("x", 129), []string{"max_length"}},
		{"common", "unbelievable", []string{"common_password"}},
		{"equal to the e-mail address", "carol@example.com", []string{"login_identifier"}},
		{"equal to the nickname in other case", "CAROL_C", []string{"min_length", "login_identifier"}},
		{"rejected by a custom check", "my leaked password!", []string{"breached"}},
		{"several rules", "leaked", []string{"min_length", "breached"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.Register(t.Context(), Registration{Identifiers: fields, Password: tc.password})
			var weak *PolicyError
			if !errors.As(err, &weak) {
				t.Fatalf("Register = %v, want a *PolicyError", err)
			}
			if strings.Join(weak.Rules, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("Rules = %v, want %v", weak.Rules, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want[0]) {
				t.Fatalf("the error text %q must list the rules", err)
			}
		})
	}
	if _, err := a.store.Identifiers().Find(t.Context(), store.DefaultTenant, "email", "carol@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a rejected registration must store nothing, Find = %v", err)
	}
	mustRegister(t, a, fields, goodPassword)
}

func TestRegisterPolicyOptions(t *testing.T) {
	a := newTestAuth(t, emailAndUsername(), WithPasswordPolicy(PasswordPolicy{
		MinLength: 8, MaxLength: 20, AllowCommon: true, AllowLoginIdentifier: true,
	}))
	mustRegister(t, a, map[string]string{"email": "dave@example.com"}, "unbelievable")
	mustRegister(t, a, map[string]string{"email": "erin@example.com", "username": "erin_e123"}, "erin_e123")
	_, err := a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "fred@example.com"}, Password: strings.Repeat("y", 21)})
	var weak *PolicyError
	if !errors.As(err, &weak) || len(weak.Rules) != 1 || weak.Rules[0] != "max_length" {
		t.Fatalf("Register = %v, want the maximum length rule", err)
	}
}

func TestRegisterIdentifierTaken(t *testing.T) {
	a := newTestAuth(t, emailAndUsername())
	first := mustRegister(t, a, map[string]string{"email": "grace@example.com", "username": "grace_g"}, goodPassword)

	cases := []struct {
		name   string
		fields map[string]string
		kind   string
	}{
		{"same e-mail address", map[string]string{"email": "grace@example.com", "username": "someone_else"}, "email"},
		{"e-mail address in other case", map[string]string{"email": " GRACE@Example.COM ", "username": "someone_else"}, "email"},
		{"same nickname", map[string]string{"email": "other@example.com", "username": "grace_g"}, "username"},
		{"nickname in other case", map[string]string{"email": "other@example.com", "username": "GRACE_G"}, "username"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.Register(t.Context(), Registration{Identifiers: tc.fields, Password: goodPassword})
			if !errors.Is(err, ErrIdentifierTaken) || !strings.Contains(err.Error(), tc.kind) {
				t.Fatalf("Register = %v, want ErrIdentifierTaken naming %q", err, tc.kind)
			}
		})
	}
	for _, leftover := range [][2]string{{"email", "other@example.com"}, {"username", "someone_else"}} {
		if _, err := a.store.Identifiers().Find(t.Context(), store.DefaultTenant, leftover[0], leftover[1]); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a failed registration must be rolled back completely, Find(%v) = %v", leftover, err)
		}
	}
	list, err := a.store.Identifiers().ListByUser(t.Context(), store.DefaultTenant, string(first.ID))
	if err != nil || len(list) != 2 {
		t.Fatalf("the first user must be untouched: %v, %v", list, err)
	}
}

func TestRegisterIsolatesTenants(t *testing.T) {
	a := newTestAuth(t)
	other := store.User{TenantID: otherTenant, ID: "00000000-0000-7000-8000-000000000001", Status: store.StatusActive, CreatedAt: time.Now()}
	if err := a.store.Users().Create(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	if err := a.store.Identifiers().Add(t.Context(), store.Identifier{TenantID: otherTenant, Type: "email", Value: "same@example.com", DisplayValue: "same@example.com", UserID: other.ID}); err != nil {
		t.Fatal(err)
	}
	mustRegister(t, a, map[string]string{"email": "same@example.com"}, goodPassword)
}

func TestRegisterConcurrentlyWithTheSameEmail(t *testing.T) {
	a := newTestAuth(t, emailAndUsername())
	const racers = 8
	var wins, taken atomic.Int32
	var wg sync.WaitGroup
	for n := range racers {
		wg.Go(func() {
			_, err := a.Register(t.Context(), Registration{
				Identifiers: map[string]string{"email": "race@example.com", "username": fmt.Sprintf("racer_%d", n)},
				Password:    goodPassword,
			})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrIdentifierTaken):
				taken.Add(1)
			default:
				t.Errorf("racer %d: unexpected error %v", n, err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 || taken.Load() != racers-1 {
		t.Fatalf("%d registrations succeeded and %d were refused; want exactly 1 and %d", wins.Load(), taken.Load(), racers-1)
	}
	survivors := 0
	for n := range racers {
		if _, err := a.store.Identifiers().Find(t.Context(), store.DefaultTenant, "username", fmt.Sprintf("racer_%d", n)); err == nil {
			survivors++
		}
	}
	if survivors != 1 {
		t.Fatalf("%d nicknames were stored, want only the one of the winner", survivors)
	}
}

func TestRegisterStoreFailures(t *testing.T) {
	boom := errors.New("database is down")
	a := newTestAuth(t)
	a.store = &faultyStore{Store: a.store, txErr: boom}
	_, err := a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "heidi@example.com"}, Password: goodPassword})
	if !errors.Is(err, boom) || errors.Is(err, ErrIdentifierTaken) {
		t.Fatalf("Register = %v, want the store error and not ErrIdentifierTaken", err)
	}

	a = newTestAuth(t)
	failing := errors.New("cannot make an ID")
	a.newID = func() (string, error) { return "", failing }
	if _, err = a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "heidi@example.com"}, Password: goodPassword}); !errors.Is(err, failing) {
		t.Fatalf("Register = %v, want %v", err, failing)
	}

	a = newTestAuth(t)
	a.newID = func() (string, error) { return "00000000-0000-7000-8000-000000000001", nil }
	mustRegister(t, a, map[string]string{"email": "ivan@example.com"}, goodPassword)
	_, err = a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "judy@example.com"}, Password: goodPassword})
	if err == nil || errors.Is(err, ErrIdentifierTaken) {
		t.Fatalf("a repeated user ID is an internal error, not a taken identifier: %v", err)
	}
}

func TestRegisterHashFailure(t *testing.T) {
	a := newTestAuth(t)
	boom := errors.New("random source failed")
	a.hasher = &countingHasher{passwordHasher: a.hasher, hashErr: boom}
	_, err := a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "kim@example.com"}, Password: goodPassword})
	if !errors.Is(err, boom) {
		t.Fatalf("Register = %v, want %v", err, boom)
	}
	if _, err = a.store.Identifiers().Find(t.Context(), store.DefaultTenant, "email", "kim@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("nothing must be stored when hashing fails, Find = %v", err)
	}
}

func TestRegisterWithACanceledContext(t *testing.T) {
	a := newTestAuth(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := a.Register(ctx, Registration{Identifiers: map[string]string{"email": "leo@example.com"}, Password: goodPassword})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Register = %v, want context.Canceled", err)
	}
	if _, err = a.store.Identifiers().Find(t.Context(), store.DefaultTenant, "email", "leo@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("nothing must be stored, Find = %v", err)
	}
}

func TestRegisterNeverLogsSecrets(t *testing.T) {
	logger, logs := capturingLogger()
	a := newTestAuth(t, emailAndUsername(), WithLogger(logger))
	mustRegister(t, a, map[string]string{"email": "mia@example.com", "username": "mia_m"}, goodPassword)
	if _, err := a.Register(t.Context(), Registration{Identifiers: map[string]string{"email": "mia@example.com"}, Password: goodPassword}); err == nil {
		t.Fatal("the second registration must fail")
	}
	if strings.Contains(logs.String(), goodPassword) || strings.Contains(logs.String(), "$argon2id$") {
		t.Fatalf("logs must not contain passwords or hashes:\n%s", logs.String())
	}
}

func TestErrorsWorkWithIsAndAs(t *testing.T) {
	validation := fmt.Errorf("wrapped: %w", &ValidationError{Field: "email", Reason: "required"})
	var gotValidation *ValidationError
	if !errors.As(validation, &gotValidation) || gotValidation.Field != "email" {
		t.Fatalf("errors.As must find a ValidationError through wrapping: %v", validation)
	}
	policy := fmt.Errorf("wrapped: %w", &PolicyError{Rules: []string{"min_length", "breached"}})
	var gotPolicy *PolicyError
	if !errors.As(policy, &gotPolicy) || len(gotPolicy.Rules) != 2 {
		t.Fatalf("errors.As must find a PolicyError through wrapping: %v", policy)
	}
	if !strings.Contains(policy.Error(), "min_length, breached") {
		t.Fatalf("the rules must be listed in the text: %v", policy)
	}
	for _, sentinel := range []error{ErrInvalidCredentials, ErrUserBlocked, ErrIdentifierTaken} {
		wrapped := fmt.Errorf("wrapped: %w", sentinel)
		if !errors.Is(wrapped, sentinel) {
			t.Errorf("errors.Is must find %v through wrapping", sentinel)
		}
		for _, other := range []error{ErrInvalidCredentials, ErrUserBlocked, ErrIdentifierTaken} {
			if !errors.Is(other, sentinel) && errors.Is(wrapped, other) {
				t.Errorf("%v must not match %v", sentinel, other)
			}
		}
		if !strings.HasPrefix(sentinel.Error(), "limb: ") {
			t.Errorf("%q must start with the package name", sentinel)
		}
	}
}
