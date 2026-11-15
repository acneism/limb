package storecheck

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func validUser() store.User {
	return store.User{TenantID: "default", ID: "u1", Status: store.StatusActive, PasswordHash: "hash", CreatedAt: time.Now()}
}

func validIdentifier() store.Identifier {
	return store.Identifier{TenantID: "default", Type: "email", Value: "a@example.com", DisplayValue: "A@example.com", UserID: "u1"}
}

func TestUserRules(t *testing.T) {
	if err := NewUser(validUser()); err != nil {
		t.Fatalf("a valid user was rejected: %v", err)
	}
	optional := validUser()
	optional.PasswordHash = ""
	optional.BlockedReason = ""
	if err := NewUser(optional); err != nil {
		t.Fatalf("a user without a password and a reason is valid: %v", err)
	}
	cases := map[string]func(*store.User){
		"no tenant":          func(u *store.User) { u.TenantID = "" },
		"no id":              func(u *store.User) { u.ID = "" },
		"no status":          func(u *store.User) { u.Status = "" },
		"unknown status":     func(u *store.User) { u.Status = "frozen" },
		"NUL in the tenant":  func(u *store.User) { u.TenantID = "a\x00b" },
		"NUL in the hash":    func(u *store.User) { u.PasswordHash = "a\x00b" },
		"bad UTF-8 reason":   func(u *store.User) { u.BlockedReason = "a\xffb" },
		"NUL in the user id": func(u *store.User) { u.ID = "a\x00" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			u := validUser()
			edit(&u)
			if err := NewUser(u); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewUser = %v, want ErrInvalid", err)
			}
			if err := User(u); !errors.Is(err, ErrInvalid) {
				t.Fatalf("User = %v, want ErrInvalid", err)
			}
		})
	}
	noCreation := validUser()
	noCreation.CreatedAt = time.Time{}
	if err := NewUser(noCreation); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "created_at") {
		t.Fatalf("NewUser without a creation time = %v", err)
	}
	if err := User(noCreation); err != nil {
		t.Fatalf("an update does not need a creation time: %v", err)
	}
	for _, status := range []store.Status{store.StatusActive, store.StatusBlocked, store.StatusDeleted} {
		u := validUser()
		u.Status = status
		if err := User(u); err != nil {
			t.Fatalf("status %q was rejected: %v", status, err)
		}
	}
}

func TestIdentifierRules(t *testing.T) {
	if err := Identifier(validIdentifier()); err != nil {
		t.Fatalf("a valid identifier was rejected: %v", err)
	}
	cases := map[string]func(*store.Identifier){
		"no tenant":     func(i *store.Identifier) { i.TenantID = "" },
		"no type":       func(i *store.Identifier) { i.Type = "" },
		"no value":      func(i *store.Identifier) { i.Value = "" },
		"no display":    func(i *store.Identifier) { i.DisplayValue = "" },
		"no user":       func(i *store.Identifier) { i.UserID = "" },
		"NUL value":     func(i *store.Identifier) { i.Value = "a\x00" },
		"bad UTF-8":     func(i *store.Identifier) { i.DisplayValue = "\xff" },
		"NUL in a type": func(i *store.Identifier) { i.Type = "e\x00" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			i := validIdentifier()
			edit(&i)
			err := Identifier(i)
			if !errors.Is(err, ErrInvalid) || !strings.HasPrefix(err.Error(), "store: invalid record: identifier ") {
				t.Fatalf("Identifier = %v, want ErrInvalid naming the field", err)
			}
		})
	}
}

func TestValidText(t *testing.T) {
	for _, ok := range []string{"", "plain", "пароль", "tab\tand\nnewline", "emoji \U0001F600"} {
		if !ValidText(ok) {
			t.Errorf("%q must be valid text", ok)
		}
	}
	for _, bad := range []string{"a\x00b", "\x00", "a\xffb", "\xc0\xaf"} {
		if ValidText(bad) {
			t.Errorf("%q must not be valid text", bad)
		}
	}
	if !ValidText() || !ValidText("a", "b") || ValidText("a", "b\x00") {
		t.Error("ValidText must require every value to be valid")
	}
}
