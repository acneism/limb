package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/google/uuid"
)

func randomMaster(t testing.TB) []byte {
	t.Helper()
	master := make([]byte, 40)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("random source failed: %v", err)
	}
	return master
}

func newKeys(t testing.TB, master []byte) *Keys {
	t.Helper()
	k, err := NewKeys(master)
	if err != nil {
		t.Fatalf("NewKeys failed: %v", err)
	}
	return k
}

func referenceHKDF(master []byte, info string) []byte {
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(master)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte(info))
	expand.Write([]byte{1})
	return expand.Sum(nil)
}

func referenceAEAD(t testing.TB, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}
	return aead
}

func referenceMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func TestNewKeysRejectsShortMasterKey(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31} {
		if k, err := NewKeys(make([]byte, n)); !errors.Is(err, ErrMasterKey) || k != nil {
			t.Fatalf("NewKeys(%d bytes) = %v, %v; want ErrMasterKey", n, k, err)
		}
	}
	for _, n := range []int{32, 33, 4096} {
		if _, err := NewKeys(make([]byte, n)); err != nil {
			t.Fatalf("NewKeys(%d bytes) failed: %v", n, err)
		}
	}
}

func TestSubkeysAreDerivedWithHKDFAndTheirOwnInfo(t *testing.T) {
	master := randomMaster(t)
	k := newKeys(t, master)
	if want := referenceHKDF(master, "limb/v1/attempts"); !bytes.Equal(k.attempts, want) {
		t.Fatalf("the attempts key is not HKDF-SHA256 with the info %q", "limb/v1/attempts")
	}
	if want := referenceHKDF(master, "limb/v1/csrf"); !bytes.Equal(k.csrf, want) {
		t.Fatalf("the CSRF key is not HKDF-SHA256 with the info %q", "limb/v1/csrf")
	}
	if bytes.Equal(k.attempts, k.csrf) {
		t.Fatal("the attempts key and the CSRF key are equal")
	}
	if bytes.Equal(referenceHKDF(master, "limb/v1/signing-keys"), k.attempts) || bytes.Equal(referenceHKDF(master, "limb/v1/signing-keys"), k.csrf) {
		t.Fatal("the sealing key equals another subkey")
	}
}

func TestSealingKeyAndFormatFollowTheSpecification(t *testing.T) {
	master := randomMaster(t)
	k := newKeys(t, master)
	reference := referenceAEAD(t, referenceHKDF(master, "limb/v1/signing-keys"))
	additional := []byte{1, 5, 'k', 'i', 'd', '-', '1', 5, 'E', 'd', 'D', 'S', 'A'}
	plaintext := []byte("private key bytes")

	sealed, err := k.Seal(plaintext, "kid-1", "EdDSA")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	if sealed[0] != 1 {
		t.Fatalf("the format version is %d, want 1", sealed[0])
	}
	got, err := reference.Open(nil, sealed[1:13], sealed[13:], additional)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("the reference AES-256-GCM cannot open the sealed data: %q, %v", got, err)
	}

	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		t.Fatalf("random source failed: %v", err)
	}
	foreign := append([]byte{1}, nonce...)
	foreign = reference.Seal(foreign, nonce, plaintext, additional)
	got, err = k.Open(foreign, "kid-1", "EdDSA")
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("Open cannot open data sealed by the reference AES-256-GCM: %q, %v", got, err)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	big := make([]byte, maxSealedLength-1-nonceLength-k.aead.Overhead())
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("random source failed: %v", err)
	}
	cases := map[string][]byte{
		"nil":     nil,
		"empty":   {},
		"one":     {7},
		"text":    []byte("a private key"),
		"largest": big,
	}
	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			sealed, err := k.Seal(plaintext, "kid", "alg")
			if err != nil {
				t.Fatalf("Seal failed: %v", err)
			}
			if want := 1 + nonceLength + len(plaintext) + k.aead.Overhead(); len(sealed) != want {
				t.Fatalf("sealed length = %d, want %d", len(sealed), want)
			}
			got, err := k.Open(sealed, "kid", "alg")
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatalf("Open = %q, %v; want %q", got, err, plaintext)
			}
		})
	}
}

func TestSealUsesAFreshNonceEachTime(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	seen := make(map[string]bool)
	for range 2000 {
		sealed, err := k.Seal([]byte("same"), "kid")
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}
		nonce := string(sealed[1 : 1+nonceLength])
		if seen[nonce] {
			t.Fatal("a nonce was used twice")
		}
		seen[nonce] = true
	}
}

func TestSealReportsRandomFailure(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	boom := errors.New("boom")
	k.random = iotest.ErrReader(boom)
	if sealed, err := k.Seal([]byte("x")); !errors.Is(err, boom) || sealed != nil {
		t.Fatalf("Seal with a failing source = %v, %v; want %v", sealed, err, boom)
	}
	k.random = bytes.NewReader(make([]byte, nonceLength-1))
	if _, err := k.Seal([]byte("x")); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Seal with a short source = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestOpenRejectsEveryDamage(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	sealed, err := k.Seal([]byte("hello"), "kid", "EdDSA")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	for i := range sealed {
		for bit := range 8 {
			damaged := bytes.Clone(sealed)
			damaged[i] ^= 1 << bit
			if got, openErr := k.Open(damaged, "kid", "EdDSA"); !errors.Is(openErr, ErrOpen) || got != nil {
				t.Fatalf("Open accepted byte %d with bit %d flipped: %q, %v", i, bit, got, openErr)
			}
		}
	}
	for n := range sealed {
		if got, openErr := k.Open(sealed[:n], "kid", "EdDSA"); !errors.Is(openErr, ErrOpen) || got != nil {
			t.Fatalf("Open accepted the first %d bytes: %q, %v", n, got, openErr)
		}
	}
	if _, err = k.Open(append(bytes.Clone(sealed), 0), "kid", "EdDSA"); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open accepted trailing data: %v", err)
	}
	if _, err = k.Open(nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open(nil) = %v, want ErrOpen", err)
	}
}

func TestOpenRejectsAnotherContext(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	sealed, err := k.Seal([]byte("hello"), "ab", "c")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	others := map[string][]string{
		"none":          nil,
		"first only":    {"ab"},
		"second only":   {"c"},
		"swapped":       {"c", "ab"},
		"shifted split": {"a", "bc"},
		"joined":        {"abc"},
		"extra empty":   {"ab", "c", ""},
		"other kid":     {"ax", "c"},
		"other alg":     {"ab", "d"},
	}
	for name, context := range others {
		if got, openErr := k.Open(sealed, context...); !errors.Is(openErr, ErrOpen) || got != nil {
			t.Errorf("%s: Open accepted another context: %q, %v", name, got, openErr)
		}
	}
	if _, err = k.Open(sealed, "ab", "c"); err != nil {
		t.Fatalf("Open with the right context failed: %v", err)
	}
	empty, err := k.Seal([]byte("hello"), "a")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	if _, err = k.Open(empty, "a", ""); !errors.Is(err, ErrOpen) {
		t.Fatalf("a trailing empty context string was ignored: %v", err)
	}
}

func TestOpenRejectsAnotherMasterKey(t *testing.T) {
	sealed, err := newKeys(t, randomMaster(t)).Seal([]byte("hello"), "kid")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	if got, err := newKeys(t, randomMaster(t)).Open(sealed, "kid"); !errors.Is(err, ErrOpen) || got != nil {
		t.Fatalf("Open with another master key = %q, %v; want ErrOpen", got, err)
	}
}

func TestOpenRejectsAnUnknownVersion(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	sealed, err := k.Seal([]byte("hello"), "kid")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	for _, version := range []byte{0, 2, 255} {
		changed := bytes.Clone(sealed)
		changed[0] = version
		if _, err = k.Open(changed, "kid"); !errors.Is(err, ErrOpen) {
			t.Fatalf("Open accepted the version %d: %v", version, err)
		}
	}
}

func TestOpenRejectsOversizedData(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	sealed, err := k.Seal(make([]byte, maxSealedLength-nonceLength-k.aead.Overhead()), "kid")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	if len(sealed) != maxSealedLength+1 {
		t.Fatalf("test data has %d bytes, want %d", len(sealed), maxSealedLength+1)
	}
	if _, err = k.Open(sealed, "kid"); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open accepted %d bytes: %v", len(sealed), err)
	}
}

func TestOpenDoesNotChangeItsInput(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	sealed, err := k.Seal([]byte("hello"), "kid")
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	before := bytes.Clone(sealed)
	plaintext, err := k.Open(sealed, "kid")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	plaintext[0] ^= 0xff
	if !bytes.Equal(sealed, before) {
		t.Fatal("Open changed its input or returned a slice of it")
	}
}

func TestCSRFTokenIsTheHMACOfTheSessionID(t *testing.T) {
	master := randomMaster(t)
	k := newKeys(t, master)
	session := uuid.NewString()
	want := encoding.EncodeToString(referenceMAC(referenceHKDF(master, "limb/v1/csrf"), []byte(session)))
	if got := k.CSRFToken(session); got != want {
		t.Fatalf("CSRFToken = %q, want %q", got, want)
	}
	if len(want) != TextLen {
		t.Fatalf("the token has %d characters, want %d", len(want), TextLen)
	}
}

func TestCheckCSRF(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	other := newKeys(t, randomMaster(t))
	token := k.CSRFToken("session-1")
	cases := []struct {
		name    string
		keys    *Keys
		session string
		token   string
		want    bool
	}{
		{"right token", k, "session-1", token, true},
		{"another session", k, "session-2", token, false},
		{"another master key", other, "session-1", token, false},
		{"empty", k, "session-1", "", false},
		{"truncated", k, "session-1", token[:len(token)-1], false},
		{"extended", k, "session-1", token + "A", false},
		{"upper case", k, "session-1", strings.ToUpper(token), false},
		{"token of the other session", k, "session-1", k.CSRFToken("session-2"), false},
		{"session ID as token", k, "session-1", "session-1", false},
	}
	for _, c := range cases {
		if got := c.keys.CheckCSRF(c.session, c.token); got != c.want {
			t.Errorf("%s: CheckCSRF = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAttemptKeyIsTheHMACOfTheFramedParts(t *testing.T) {
	master := randomMaster(t)
	k := newKeys(t, master)
	framed := []byte{2, 'i', 'p', 7, 'd', 'e', 'f', 'a', 'u', 'l', 't', 11, '2', '0', '3', '.', '0', '.', '1', '1', '3', '.', '7'}
	want := encoding.EncodeToString(referenceMAC(referenceHKDF(master, "limb/v1/attempts"), framed))
	if got := k.AttemptKey("ip", "default", "203.0.113.7"); got != want {
		t.Fatalf("AttemptKey = %q, want %q", got, want)
	}
	if len(want) != TextLen {
		t.Fatalf("the key has %d characters, want %d", len(want), TextLen)
	}
}

func TestAttemptKeysDoNotCollide(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	other := newKeys(t, randomMaster(t))
	all := []string{
		k.AttemptKey("account", "default", "alice"),
		k.AttemptKey("account", "default", "bob"),
		k.AttemptKey("account", "other", "alice"),
		k.AttemptKey("ip", "default", "alice"),
		k.AttemptKey("account", "alice", "default"),
		k.AttemptKey("account", "default"),
		k.AttemptKey("account", "default", "alice", ""),
		k.AttemptKey("account", "ab", "c"),
		k.AttemptKey("account", "a", "bc"),
		k.AttemptKey("account", "abc"),
		k.AttemptKey("account"),
		k.AttemptKey("accoun", "t"),
		k.AttemptKey(""),
		other.AttemptKey("account", "default", "alice"),
	}
	seen := make(map[string]int)
	for i, key := range all {
		if j, ok := seen[key]; ok {
			t.Errorf("attempt keys %d and %d are equal", j, i)
		}
		seen[key] = i
	}
	if k.AttemptKey("account", "default", "alice") != all[0] {
		t.Fatal("AttemptKey is not deterministic")
	}
}

func fuzzKeys(t testing.TB) *Keys {
	t.Helper()
	return newKeys(t, bytes.Repeat([]byte{0x42}, MinMasterKeyLength))
}

func FuzzOpen(f *testing.F) {
	k := fuzzKeys(f)
	valid, err := k.Seal([]byte("private key"), "kid", "EdDSA")
	if err != nil {
		f.Fatalf("Seal failed: %v", err)
	}
	empty, err := k.Seal(nil)
	if err != nil {
		f.Fatalf("Seal failed: %v", err)
	}
	f.Add(valid, "kid", "EdDSA")
	f.Add(valid, "kid", "ES256")
	f.Add(valid, "", "")
	f.Add(empty, "", "")
	f.Add(valid[:len(valid)-1], "kid", "EdDSA")
	f.Add(valid[:1], "", "")
	f.Add([]byte{}, "", "")
	f.Add([]byte{1}, "", "")
	f.Add(append([]byte{2}, valid[1:]...), "kid", "EdDSA")
	f.Add(bytes.Repeat([]byte{1}, 64), "a", "b")
	f.Fuzz(func(t *testing.T, sealed []byte, first, second string) {
		before := bytes.Clone(sealed)
		plaintext, err := k.Open(sealed, first, second)
		if !bytes.Equal(sealed, before) {
			t.Fatal("Open changed its input")
		}
		if err != nil {
			if !errors.Is(err, ErrOpen) || plaintext != nil {
				t.Fatalf("Open = %q, %v; want ErrOpen and no data", plaintext, err)
			}
			return
		}
		again, err := k.Seal(plaintext, first, second)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}
		back, err := k.Open(again, first, second)
		if err != nil || !bytes.Equal(back, plaintext) {
			t.Fatalf("a round trip of an opened value gave %q, %v; want %q", back, err, plaintext)
		}
	})
}

func FuzzSealOpen(f *testing.F) {
	k := fuzzKeys(f)
	f.Add([]byte("private key"), "kid", "EdDSA")
	f.Add([]byte{}, "", "")
	f.Add([]byte{0, 0, 0}, "a", "")
	f.Add([]byte("x"), "\x00", "\xff")
	f.Add([]byte("x"), strings.Repeat("k", 300), "é")
	f.Fuzz(func(t *testing.T, plaintext []byte, first, second string) {
		sealed, err := k.Seal(plaintext, first, second)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}
		got, err := k.Open(sealed, first, second)
		if len(sealed) > maxSealedLength {
			if !errors.Is(err, ErrOpen) {
				t.Fatalf("Open accepted %d bytes: %v", len(sealed), err)
			}
			return
		}
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("Open = %q, %v; want %q", got, err, plaintext)
		}
		if _, err = k.Open(sealed, first); err == nil {
			t.Fatalf("Open accepted a context without the second string %q", second)
		}
		if first != second {
			if _, err = k.Open(sealed, second, first); err == nil {
				t.Fatalf("Open accepted the swapped context %q, %q", second, first)
			}
		}
	})
}
