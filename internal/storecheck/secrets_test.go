package storecheck

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func validSecret(kind store.SecretKind) store.Secret {
	now := time.Now()
	return store.Secret{
		TenantID: "default", ID: "s1", Kind: kind, Hash: bytes.Repeat([]byte{1}, store.SecretHashLength), UserID: "u1",
		Purpose: store.PurposeReset, ChannelType: "email", ChannelValue: "a@example.com", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func TestSecretRules(t *testing.T) {
	for _, kind := range []store.SecretKind{store.SecretLink, store.SecretCode} {
		if err := NewSecret(validSecret(kind)); err != nil {
			t.Fatalf("a valid %s was rejected: %v", kind, err)
		}
	}
	verify := validSecret(store.SecretCode)
	verify.Purpose = store.PurposeVerify
	if err := NewSecret(verify); err != nil {
		t.Fatalf("a valid secret for verification was rejected: %v", err)
	}
	cases := map[string]func(*store.Secret){
		"no tenant":             func(s *store.Secret) { s.TenantID = "" },
		"no ID":                 func(s *store.Secret) { s.ID = "" },
		"no user":               func(s *store.Secret) { s.UserID = "" },
		"no kind":               func(s *store.Secret) { s.Kind = "" },
		"an unknown kind":       func(s *store.Secret) { s.Kind = "token" },
		"no purpose":            func(s *store.Secret) { s.Purpose = "" },
		"an unknown purpose":    func(s *store.Secret) { s.Purpose = "invite" },
		"no hash":               func(s *store.Secret) { s.Hash = nil },
		"a short hash":          func(s *store.Secret) { s.Hash = s.Hash[:store.SecretHashLength-1] },
		"a long hash":           func(s *store.Secret) { s.Hash = append(bytes.Clone(s.Hash), 0) },
		"no channel type":       func(s *store.Secret) { s.ChannelType = "" },
		"no channel value":      func(s *store.Secret) { s.ChannelValue = "" },
		"a long channel type":   func(s *store.Secret) { s.ChannelType = strings.Repeat("a", store.MaxIdentifierTypeLength+1) },
		"a long channel value":  func(s *store.Secret) { s.ChannelValue = strings.Repeat("a", store.MaxIdentifierValueLength+1) },
		"a long ID":             func(s *store.Secret) { s.ID = strings.Repeat("a", store.MaxIDLength+1) },
		"a NUL in the ID":       func(s *store.Secret) { s.ID = "a\x00" },
		"a bad UTF-8 user":      func(s *store.Secret) { s.UserID = "\xff" },
		"attempts":              func(s *store.Secret) { s.Attempts = 1 },
		"no creation time":      func(s *store.Secret) { s.CreatedAt = time.Time{} },
		"no expiry":             func(s *store.Secret) { s.ExpiresAt = time.Time{} },
		"an expiry before":      func(s *store.Secret) { s.ExpiresAt = s.CreatedAt.Add(-time.Second) },
		"an expiry at the time": func(s *store.Secret) { s.ExpiresAt = s.CreatedAt },
		"a use":                 func(s *store.Secret) { s.UsedAt = time.Now() },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := validSecret(store.SecretLink)
			edit(&s)
			if err := NewSecret(s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewSecret = %v, want ErrInvalid", err)
			}
		})
	}
	longest := validSecret(store.SecretLink)
	longest.ID = strings.Repeat("a", store.MaxIDLength)
	longest.TenantID = strings.Repeat("a", store.MaxTenantIDLength)
	longest.ChannelType = strings.Repeat("a", store.MaxIdentifierTypeLength)
	longest.ChannelValue = strings.Repeat("a", store.MaxIdentifierValueLength)
	if err := NewSecret(longest); err != nil {
		t.Fatalf("the longest allowed values were rejected: %v", err)
	}
}

func TestSecretScopeRules(t *testing.T) {
	valid := []store.SecretScope{
		{TenantID: "default", UserID: "u1", Purpose: store.PurposeReset},
		{TenantID: "default", UserID: "u1", Purpose: store.PurposeVerify, ChannelType: "email", ChannelValue: "a@example.com"},
	}
	for _, scope := range valid {
		if err := SecretScope(scope); err != nil {
			t.Errorf("SecretScope(%+v) = %v, want nil", scope, err)
		}
	}
	invalid := map[string]store.SecretScope{
		"no purpose":                {TenantID: "default", UserID: "u1"},
		"an unknown purpose":        {TenantID: "default", UserID: "u1", Purpose: "other"},
		"a channel type alone":      {TenantID: "default", UserID: "u1", Purpose: store.PurposeReset, ChannelType: "email"},
		"a channel value alone":     {TenantID: "default", UserID: "u1", Purpose: store.PurposeReset, ChannelValue: "a@example.com"},
		"a purpose of another case": {TenantID: "default", UserID: "u1", Purpose: "Reset"},
	}
	for name, scope := range invalid {
		if err := SecretScope(scope); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: SecretScope = %v, want ErrInvalid", name, err)
		}
	}
}

func TestValidScope(t *testing.T) {
	scope := store.SecretScope{TenantID: "default", UserID: "u1", Purpose: store.PurposeReset, ChannelType: "email", ChannelValue: "a@example.com"}
	if !ValidScope(scope) {
		t.Fatal("a valid scope was refused")
	}
	for name, edit := range map[string]func(*store.SecretScope){
		"a NUL in the tenant":  func(s *store.SecretScope) { s.TenantID = "a\x00" },
		"bad UTF-8 in a user":  func(s *store.SecretScope) { s.UserID = "\xff" },
		"a NUL in the type":    func(s *store.SecretScope) { s.ChannelType = "e\x00" },
		"a very long value":    func(s *store.SecretScope) { s.ChannelValue = strings.Repeat("a", store.MaxIdentifierValueLength+1) },
		"a very long tenant":   func(s *store.SecretScope) { s.TenantID = strings.Repeat("\U0001F600", 1000) },
		"bad UTF-8 in a value": func(s *store.SecretScope) { s.ChannelValue = "\xc3" },
	} {
		changed := scope
		edit(&changed)
		if ValidScope(changed) {
			t.Errorf("%s: the scope was accepted", name)
		}
	}
}

func TestAttemptLimitRule(t *testing.T) {
	for _, limit := range []int{1, 5, 1000} {
		if err := Attempts(limit); err != nil {
			t.Errorf("Attempts(%d) = %v, want nil", limit, err)
		}
	}
	for _, limit := range []int{0, -1, -1000} {
		if err := Attempts(limit); !errors.Is(err, ErrInvalid) {
			t.Errorf("Attempts(%d) = %v, want ErrInvalid", limit, err)
		}
	}
}

func TestPurposeRule(t *testing.T) {
	for _, purpose := range []store.SecretPurpose{store.PurposeVerify, store.PurposeReset} {
		if err := Purpose(purpose); err != nil {
			t.Errorf("Purpose(%q) = %v, want nil", purpose, err)
		}
	}
	for _, purpose := range []store.SecretPurpose{"", "invite", "VERIFY", "reset ", "verify\x00"} {
		if err := Purpose(purpose); !errors.Is(err, ErrInvalid) {
			t.Errorf("Purpose(%q) = %v, want ErrInvalid", purpose, err)
		}
	}
}

func TestSecretsAreOrderedByCreationTimeAndThenByID(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	a := store.Secret{ID: "a", CreatedAt: base}
	b := store.Secret{ID: "b", CreatedAt: base}
	late := store.Secret{ID: "0", CreatedAt: base.Add(time.Second)}
	list := []store.Secret{late, b, a}
	slices.SortFunc(list, CompareSecrets)
	if list[0].ID != "a" || list[1].ID != "b" || list[2].ID != "0" {
		t.Fatalf("order = %s %s %s, want a b 0", list[0].ID, list[1].ID, list[2].ID)
	}
	if CompareSecrets(a, a) != 0 || CompareSecrets(a, b) >= 0 || CompareSecrets(b, a) <= 0 || CompareSecrets(a, late) >= 0 || CompareSecrets(late, a) <= 0 {
		t.Fatal("CompareSecrets is not an order")
	}
}
