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

func TestFieldLimitsCountBytes(t *testing.T) {
	user := func(edit func(*store.User, string)) func(string) error {
		return func(v string) error {
			u := validUser()
			edit(&u, v)
			return NewUser(u)
		}
	}
	identifier := func(edit func(*store.Identifier, string)) func(string) error {
		return func(v string) error {
			i := validIdentifier()
			edit(&i, v)
			return Identifier(i)
		}
	}
	session := func(edit func(*store.Session, string)) func(string) error {
		return func(v string) error {
			s := validCookieSession()
			edit(&s, v)
			return NewSession(s)
		}
	}
	refreshToken := func(edit func(*store.RefreshToken, string)) func(string) error {
		return func(v string) error {
			r := store.RefreshToken{TenantID: "default", Hash: make([]byte, store.SecretHashLength), SessionID: "s1", ExpiresAt: time.Now()}
			edit(&r, v)
			return NewRefreshToken(r)
		}
	}
	signingKey := func(edit func(*store.SigningKey, string)) func(string) error {
		return func(v string) error {
			k := store.SigningKey{
				KID: "kid-1", Algorithm: "EdDSA", Generation: 1, PrivateKey: []byte{1}, PublicKey: []byte{2}, CreatedAt: time.Now(),
			}
			edit(&k, v)
			return NewSigningKey(k)
		}
	}
	fields := []struct {
		name  string
		check func(string) error
		limit int
	}{
		{"user tenant_id", user(func(u *store.User, v string) { u.TenantID = v }), store.MaxTenantIDLength},
		{"user id", user(func(u *store.User, v string) { u.ID = v }), store.MaxIDLength},
		{"user password_hash", user(func(u *store.User, v string) { u.PasswordHash = v }), store.MaxPasswordHashLength},
		{"user blocked_reason", user(func(u *store.User, v string) { u.BlockedReason = v }), store.MaxBlockedReasonLength},
		{"identifier tenant_id", identifier(func(i *store.Identifier, v string) { i.TenantID = v }), store.MaxTenantIDLength},
		{"identifier type", identifier(func(i *store.Identifier, v string) { i.Type = v }), store.MaxIdentifierTypeLength},
		{"identifier value", identifier(func(i *store.Identifier, v string) { i.Value = v }), store.MaxIdentifierValueLength},
		{"identifier display_value", identifier(func(i *store.Identifier, v string) { i.DisplayValue = v }), store.MaxDisplayValueLength},
		{"identifier user_id", identifier(func(i *store.Identifier, v string) { i.UserID = v }), store.MaxIDLength},
		{"session tenant_id", session(func(s *store.Session, v string) { s.TenantID = v }), store.MaxTenantIDLength},
		{"session id", session(func(s *store.Session, v string) { s.ID = v }), store.MaxIDLength},
		{"session user_id", session(func(s *store.Session, v string) { s.UserID = v }), store.MaxIDLength},
		{"session ip", session(func(s *store.Session, v string) { s.IP = v }), store.MaxIPLength},
		{"session user_agent", session(func(s *store.Session, v string) { s.UserAgent = v }), store.MaxUserAgentLength},
		{"refresh token tenant_id", refreshToken(func(r *store.RefreshToken, v string) { r.TenantID = v }), store.MaxTenantIDLength},
		{"refresh token session_id", refreshToken(func(r *store.RefreshToken, v string) { r.SessionID = v }), store.MaxIDLength},
		{"attempt key", AttemptKey, store.MaxAttemptKeyLength},
		{"signing key kid", signingKey(func(k *store.SigningKey, v string) { k.KID = v }), store.MaxKIDLength},
		{"signing key algorithm", signingKey(func(k *store.SigningKey, v string) { k.Algorithm = v }), store.MaxAlgorithmLength},
	}
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			accepted := map[string]string{
				"the limit in ASCII":                strings.Repeat("a", f.limit),
				"the limit in two byte characters":  strings.Repeat("é", f.limit/2),
				"the limit in four byte characters": strings.Repeat("\U0001F600", f.limit/4),
			}
			for name, value := range accepted {
				if err := f.check(value); err != nil {
					t.Errorf("%s (%d bytes) was rejected: %v", name, len(value), err)
				}
			}
			rejected := map[string]string{
				"one byte over the limit":                     strings.Repeat("a", f.limit+1),
				"two byte characters over the limit":          strings.Repeat("é", f.limit/2+1),
				"four byte characters over the limit":         strings.Repeat("\U0001F600", f.limit/4+1),
				"characters that would fit if counted as one": strings.Repeat("я", f.limit),
			}
			for name, value := range rejected {
				err := f.check(value)
				if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "bytes") {
					t.Errorf("%s (%d bytes): %v, want ErrInvalid that names the limit", name, len(value), err)
				}
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

func TestValidTextHasALimitInBytes(t *testing.T) {
	longest := store.MaxIdentifierValueLength
	for name, ok := range map[string]string{
		"ASCII":                strings.Repeat("a", longest),
		"two byte characters":  strings.Repeat("é", longest/2),
		"four byte characters": strings.Repeat("\U0001F600", longest/4),
	} {
		if !ValidText(ok) || !ValidText("a", ok) {
			t.Errorf("%s (%d bytes) must be valid text", name, len(ok))
		}
	}
	for name, bad := range map[string]string{
		"ASCII":                strings.Repeat("a", longest+1),
		"two byte characters":  strings.Repeat("é", longest/2+1),
		"four byte characters": strings.Repeat("\U0001F600", longest/4+1),
	} {
		if ValidText(bad) || ValidText("a", bad) {
			t.Errorf("%s (%d bytes) must not be valid text", name, len(bad))
		}
	}
}

func TestCompareIdentifiersIsByteOrder(t *testing.T) {
	typed := func(typ, value string) store.Identifier {
		return store.Identifier{Type: typ, Value: value}
	}
	cases := []struct {
		name string
		a, b store.Identifier
		want int
	}{
		{"equal", typed("email", "a"), typed("email", "a"), 0},
		{"type decides first", typed("email", "z"), typed("nick", "a"), -1},
		{"upper case sorts before lower case", typed("Phone", "x"), typed("email", "x"), -1},
		{"value decides within a type", typed("nick", "B"), typed("nick", "a"), -1},
		{"a hyphen sorts before a letter", typed("nick", "a-c"), typed("nick", "ab"), -1},
		{"a prefix sorts first", typed("nick", "a"), typed("nick", "ab"), -1},
		{"bytes of multibyte characters", typed("nick", "é"), typed("nick", "я"), -1},
		{"non ASCII after ASCII", typed("nick", "z"), typed("nick", "é"), -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CompareIdentifiers(tc.a, tc.b); got != tc.want {
				t.Fatalf("CompareIdentifiers(%v, %v) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			if got := CompareIdentifiers(tc.b, tc.a); got != -tc.want {
				t.Fatalf("the reverse comparison = %d, want %d", got, -tc.want)
			}
		})
	}
}
