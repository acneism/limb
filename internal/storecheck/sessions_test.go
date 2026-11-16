package storecheck

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/acneism/limb/store"
)

func validCookieSession() store.Session {
	now := time.Now()
	return store.Session{
		TenantID: "default", ID: "s1", Kind: store.SessionCookie, SecretHash: make([]byte, store.SecretHashLength),
		UserID: "u1", IP: "203.0.113.7", UserAgent: "agent", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func validTokenSession() store.Session {
	s := validCookieSession()
	s.Kind = store.SessionToken
	s.SecretHash = nil
	return s
}

func TestSessionRules(t *testing.T) {
	for name, s := range map[string]store.Session{"cookie": validCookieSession(), "token": validTokenSession()} {
		if err := NewSession(s); err != nil {
			t.Fatalf("a valid %s session was rejected: %v", name, err)
		}
	}
	unknown := validCookieSession()
	unknown.IP, unknown.UserAgent = "", ""
	if err := NewSession(unknown); err != nil {
		t.Fatalf("a session without an address and a user agent is valid: %v", err)
	}
	cases := map[string]func(*store.Session){
		"no tenant":                func(s *store.Session) { s.TenantID = "" },
		"no id":                    func(s *store.Session) { s.ID = "" },
		"no user":                  func(s *store.Session) { s.UserID = "" },
		"unknown kind":             func(s *store.Session) { s.Kind = "other" },
		"no kind":                  func(s *store.Session) { s.Kind = "" },
		"cookie without a hash":    func(s *store.Session) { s.SecretHash = nil },
		"cookie with a short hash": func(s *store.Session) { s.SecretHash = make([]byte, store.SecretHashLength-1) },
		"cookie with a long hash":  func(s *store.Session) { s.SecretHash = make([]byte, store.SecretHashLength+1) },
		"token with a hash":        func(s *store.Session) { s.Kind = store.SessionToken },
		"NUL in the id":            func(s *store.Session) { s.ID = "a\x00" },
		"bad UTF-8 address":        func(s *store.Session) { s.IP = "\xff" },
		"long address":             func(s *store.Session) { s.IP = strings.Repeat("1", store.MaxIPLength+1) },
		"long user agent":          func(s *store.Session) { s.UserAgent = strings.Repeat("a", store.MaxUserAgentLength+1) },
		"NUL in the user agent":    func(s *store.Session) { s.UserAgent = "a\x00b" },
		"no creation time":         func(s *store.Session) { s.CreatedAt = time.Time{} },
		"no last seen time":        func(s *store.Session) { s.LastSeenAt = time.Time{} },
		"no expiry":                func(s *store.Session) { s.ExpiresAt = time.Time{} },
		"already revoked":          func(s *store.Session) { s.RevokedAt = time.Now() },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := validCookieSession()
			edit(&s)
			if err := NewSession(s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewSession = %v, want ErrInvalid", err)
			}
		})
	}
	longest := validCookieSession()
	longest.IP = strings.Repeat("1", store.MaxIPLength)
	longest.UserAgent = strings.Repeat("a", store.MaxUserAgentLength)
	if err := NewSession(longest); err != nil {
		t.Fatalf("the longest allowed address and user agent were rejected: %v", err)
	}
}

func TestRefreshTokenRules(t *testing.T) {
	valid := store.RefreshToken{TenantID: "default", Hash: make([]byte, store.SecretHashLength), SessionID: "s1", ExpiresAt: time.Now()}
	if err := NewRefreshToken(valid); err != nil {
		t.Fatalf("a valid refresh token was rejected: %v", err)
	}
	cases := map[string]func(*store.RefreshToken){
		"no tenant":     func(r *store.RefreshToken) { r.TenantID = "" },
		"no session":    func(r *store.RefreshToken) { r.SessionID = "" },
		"no hash":       func(r *store.RefreshToken) { r.Hash = nil },
		"short hash":    func(r *store.RefreshToken) { r.Hash = make([]byte, 31) },
		"long hash":     func(r *store.RefreshToken) { r.Hash = make([]byte, 33) },
		"no expiry":     func(r *store.RefreshToken) { r.ExpiresAt = time.Time{} },
		"already used":  func(r *store.RefreshToken) { r.UsedAt = time.Now() },
		"NUL in the id": func(r *store.RefreshToken) { r.SessionID = "a\x00" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			r := valid
			edit(&r)
			if err := NewRefreshToken(r); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewRefreshToken = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestValidHash(t *testing.T) {
	for n, want := range map[int]bool{0: false, 1: false, 31: false, 32: true, 33: false} {
		if got := ValidHash(make([]byte, n)); got != want {
			t.Errorf("ValidHash(%d bytes) = %v, want %v", n, got, want)
		}
	}
	if ValidHash(nil) {
		t.Error("ValidHash(nil) = true")
	}
}

func TestAttemptKeyRules(t *testing.T) {
	for _, key := range []string{"k", strings.Repeat("k", store.MaxAttemptKeyLength)} {
		if err := AttemptKey(key); err != nil {
			t.Fatalf("AttemptKey(%d bytes) failed: %v", len(key), err)
		}
	}
	for name, key := range map[string]string{
		"empty": "", "too long": strings.Repeat("k", store.MaxAttemptKeyLength+1), "NUL": "a\x00", "bad UTF-8": "\xff",
	} {
		if err := AttemptKey(key); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: AttemptKey = %v, want ErrInvalid", name, err)
		}
		if ValidAttemptKey(key) {
			t.Errorf("%s: ValidAttemptKey = true", name)
		}
	}
	if !ValidAttemptKey("k") {
		t.Error("ValidAttemptKey rejected a good key")
	}
}

func TestSigningKeyRules(t *testing.T) {
	valid := store.SigningKey{
		KID: "kid-1", Algorithm: "EdDSA", Generation: 1, PrivateKey: []byte{1}, PublicKey: []byte{2}, CreatedAt: time.Now(),
	}
	if err := NewSigningKey(valid); err != nil {
		t.Fatalf("a valid signing key was rejected: %v", err)
	}
	cases := map[string]func(*store.SigningKey){
		"no kid":              func(k *store.SigningKey) { k.KID = "" },
		"long kid":            func(k *store.SigningKey) { k.KID = strings.Repeat("k", store.MaxKIDLength+1) },
		"NUL in the kid":      func(k *store.SigningKey) { k.KID = "a\x00" },
		"no algorithm":        func(k *store.SigningKey) { k.Algorithm = "" },
		"long algorithm":      func(k *store.SigningKey) { k.Algorithm = strings.Repeat("a", store.MaxAlgorithmLength+1) },
		"zero generation":     func(k *store.SigningKey) { k.Generation = 0 },
		"negative":            func(k *store.SigningKey) { k.Generation = -1 },
		"no private key":      func(k *store.SigningKey) { k.PrivateKey = nil },
		"no public key":       func(k *store.SigningKey) { k.PublicKey = []byte{} },
		"long private key":    func(k *store.SigningKey) { k.PrivateKey = make([]byte, store.MaxKeyMaterialLength+1) },
		"long public key":     func(k *store.SigningKey) { k.PublicKey = make([]byte, store.MaxKeyMaterialLength+1) },
		"no creation time":    func(k *store.SigningKey) { k.CreatedAt = time.Time{} },
		"already retired":     func(k *store.SigningKey) { k.RetireAfter = time.Now() },
		"bad UTF-8 algorithm": func(k *store.SigningKey) { k.Algorithm = "\xff" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			k := valid
			edit(&k)
			if err := NewSigningKey(k); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewSigningKey = %v, want ErrInvalid", err)
			}
		})
	}
	longest := valid
	longest.KID = strings.Repeat("k", store.MaxKIDLength)
	longest.Algorithm = strings.Repeat("a", store.MaxAlgorithmLength)
	longest.PrivateKey = make([]byte, store.MaxKeyMaterialLength)
	longest.PublicKey = make([]byte, store.MaxKeyMaterialLength)
	if err := NewSigningKey(longest); err != nil {
		t.Fatalf("the longest allowed kid and algorithm were rejected: %v", err)
	}
}

func TestCompareSessions(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	early := store.Session{ID: "z", CreatedAt: base}
	late := store.Session{ID: "a", CreatedAt: base.Add(time.Microsecond)}
	sameTimeLowID := store.Session{ID: "A", CreatedAt: base}
	sameTimeHighID := store.Session{ID: "a", CreatedAt: base}
	if CompareSessions(early, late) >= 0 || CompareSessions(late, early) <= 0 {
		t.Error("an earlier session does not come first")
	}
	if CompareSessions(sameTimeLowID, sameTimeHighID) >= 0 || CompareSessions(sameTimeHighID, sameTimeLowID) <= 0 {
		t.Error("IDs are not compared byte by byte")
	}
	if CompareSessions(early, early) != 0 {
		t.Error("equal sessions do not compare equal")
	}
	list := []store.Session{late, sameTimeHighID, early, sameTimeLowID}
	slices.SortFunc(list, CompareSessions)
	var got []string
	for _, s := range list {
		got = append(got, s.ID+"@"+s.CreatedAt.Format("05.000000"))
	}
	if want := []string{"A@05.000000", "a@05.000000", "z@05.000000", "a@05.000001"}; !slices.Equal(got, want) {
		t.Fatalf("sorted sessions = %v, want %v", got, want)
	}
}

func TestTimeRule(t *testing.T) {
	if err := Time("moment", time.Now()); err != nil {
		t.Fatalf("a set time was rejected: %v", err)
	}
	if err := Time("moment", time.Time{}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "moment") {
		t.Fatalf("a zero time = %v, want ErrInvalid that names the field", err)
	}
}

func TestWindowRule(t *testing.T) {
	if err := Window(time.Nanosecond); err != nil {
		t.Fatalf("a positive window was rejected: %v", err)
	}
	for _, window := range []time.Duration{0, -time.Second} {
		if err := Window(window); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Window(%v) = %v, want ErrInvalid", window, err)
		}
	}
}
