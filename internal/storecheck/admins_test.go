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

func validAdmin() store.Admin {
	return store.Admin{
		TenantID: "default", ID: "a1", Login: "root", PasswordHash: "hash", Status: store.AdminActive, CreatedAt: time.Now(),
	}
}

func TestAdminRules(t *testing.T) {
	if err := NewAdmin(validAdmin()); err != nil {
		t.Fatalf("a valid administrator was rejected: %v", err)
	}
	bound := validAdmin()
	bound.TOTPSecret = bytes.Repeat([]byte{1}, store.MaxSealedSecretLength)
	bound.TOTPConfirmedAt = time.Now()
	bound.TOTPLastStep = 7
	bound.LastLoginAt = time.Now()
	bound.Status = store.AdminDisabled
	if err := NewAdmin(bound); err != nil {
		t.Fatalf("an administrator with an authenticator was rejected: %v", err)
	}
	cases := map[string]func(*store.Admin){
		"no tenant":                       func(a *store.Admin) { a.TenantID = "" },
		"no ID":                           func(a *store.Admin) { a.ID = "" },
		"no login":                        func(a *store.Admin) { a.Login = "" },
		"no password":                     func(a *store.Admin) { a.PasswordHash = "" },
		"no status":                       func(a *store.Admin) { a.Status = "" },
		"an unknown status":               func(a *store.Admin) { a.Status = "frozen" },
		"a long login":                    func(a *store.Admin) { a.Login = strings.Repeat("a", store.MaxAdminLoginLength+1) },
		"a long password":                 func(a *store.Admin) { a.PasswordHash = strings.Repeat("a", store.MaxPasswordHashLength+1) },
		"a long tenant":                   func(a *store.Admin) { a.TenantID = strings.Repeat("a", store.MaxTenantIDLength+1) },
		"a long ID":                       func(a *store.Admin) { a.ID = strings.Repeat("a", store.MaxIDLength+1) },
		"a long secret":                   func(a *store.Admin) { a.TOTPSecret = make([]byte, store.MaxSealedSecretLength+1) },
		"a confirmation without a secret": func(a *store.Admin) { a.TOTPConfirmedAt = time.Now() },
		"a NUL in the login":              func(a *store.Admin) { a.Login = "a\x00" },
		"a bad UTF-8 login":               func(a *store.Admin) { a.Login = "\xff" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			a := validAdmin()
			edit(&a)
			if err := NewAdmin(a); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewAdmin = %v, want ErrInvalid", err)
			}
			if err := Admin(a); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Admin = %v, want ErrInvalid", err)
			}
		})
	}
	noTime := validAdmin()
	noTime.CreatedAt = time.Time{}
	if err := NewAdmin(noTime); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewAdmin without a creation time = %v, want ErrInvalid", err)
	}
	if err := Admin(noTime); err != nil {
		t.Fatalf("an update does not need the creation time: %v", err)
	}
	negative := validAdmin()
	negative.TOTPLastStep = -1
	if err := NewAdmin(negative); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewAdmin with a negative step = %v, want ErrInvalid", err)
	}
}

func TestRecoveryHashRules(t *testing.T) {
	hash := func(b byte) []byte { return bytes.Repeat([]byte{b}, store.SecretHashLength) }
	if err := RecoveryHashes(nil); err != nil {
		t.Fatalf("no hashes were rejected: %v", err)
	}
	if err := RecoveryHashes([][]byte{hash(1), hash(2)}); err != nil {
		t.Fatalf("two hashes were rejected: %v", err)
	}
	many := make([][]byte, store.MaxRecoveryCodes)
	for i := range many {
		many[i] = bytes.Repeat([]byte{byte(i + 1)}, store.SecretHashLength)
	}
	if err := RecoveryHashes(many); err != nil {
		t.Fatalf("the most hashes that are allowed were rejected: %v", err)
	}
	for name, hashes := range map[string][][]byte{
		"too many":      slices.Concat(many, [][]byte{hash(200)}),
		"a short hash":  {hash(1)[:31]},
		"a long hash":   {append(hash(1), 0)},
		"an empty hash": {nil},
		"a repeat":      {hash(1), hash(2), hash(1)},
		"a next repeat": {hash(1), hash(1)},
	} {
		if err := RecoveryHashes(hashes); !errors.Is(err, ErrInvalid) {
			t.Errorf("RecoveryHashes with %s = %v, want ErrInvalid", name, err)
		}
	}
}

func TestAdminsAreComparedByTheBytesOfTheirLogins(t *testing.T) {
	compare := func(a, b string) int { return CompareAdmins(store.Admin{Login: a}, store.Admin{Login: b}) }
	if compare("a", "b") >= 0 || compare("b", "a") <= 0 || compare("a", "a") != 0 || compare("Z", "a") >= 0 || compare("é", "z") <= 0 {
		t.Fatal("the logins must be compared byte by byte")
	}
}
