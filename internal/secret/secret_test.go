package secret

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func mustNew(t testing.TB) string {
	t.Helper()
	text, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return text
}

func TestNewIsCanonicalAndUnique(t *testing.T) {
	seen := make(map[string]bool)
	for range 2000 {
		text := mustNew(t)
		if len(text) != TextLen {
			t.Fatalf("New() = %q has %d characters, want %d", text, len(text), TextLen)
		}
		raw, err := encoding.DecodeString(text)
		if err != nil || len(raw) != Bytes {
			t.Fatalf("New() = %q is not the canonical text of %d bytes: %v", text, Bytes, err)
		}
		if seen[text] {
			t.Fatalf("New() returned %q twice", text)
		}
		seen[text] = true
	}
}

func TestNewFromEncodesURLSafeWithoutPadding(t *testing.T) {
	raw := bytes.Repeat([]byte{0xfb, 0xff, 0xbf}, 11)[:Bytes]
	got, err := newFrom(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("newFrom failed: %v", err)
	}
	if want := base64.RawURLEncoding.EncodeToString(raw); got != want {
		t.Fatalf("newFrom = %q, want %q", got, want)
	}
	if !strings.ContainsAny(got, "-_") || strings.ContainsAny(got, "+/=") {
		t.Fatalf("newFrom = %q is not base64url without padding", got)
	}
}

func TestNewFromReportsRandomFailure(t *testing.T) {
	boom := errors.New("boom")
	if _, err := newFrom(iotest.ErrReader(boom)); !errors.Is(err, boom) {
		t.Fatalf("newFrom with a failing source = %v, want %v", err, boom)
	}
	if _, err := newFrom(bytes.NewReader(make([]byte, Bytes-1))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("newFrom with a short source = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestHashIsDigestOfTheText(t *testing.T) {
	text := mustNew(t)
	got, err := Hash(text)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}
	want := sha256.Sum256([]byte(text))
	if len(got) != HashLen || !bytes.Equal(got, want[:]) {
		t.Fatalf("Hash(%q) = %x, want %x", text, got, want)
	}
	other, err := Hash(mustNew(t))
	if err != nil || bytes.Equal(got, other) {
		t.Fatalf("hashes of different secrets are equal or failed: %v", err)
	}
}

func TestHashRejectsMalformedText(t *testing.T) {
	valid := mustNew(t)
	cases := map[string]string{
		"empty":                "",
		"one short":            valid[:TextLen-1],
		"one long":             valid + "A",
		"double":               valid + valid,
		"huge":                 strings.Repeat("A", 1<<20),
		"standard alphabet +":  strings.Repeat("A", TextLen-1) + "+",
		"standard alphabet /":  strings.Repeat("A", TextLen-1) + "/",
		"padding":              valid[:TextLen-1] + "=",
		"space":                valid[:TextLen-1] + " ",
		"leading space":        " " + valid[:TextLen-1],
		"newline":              valid[:TextLen-1] + "\n",
		"nul":                  valid[:TextLen-1] + "\x00",
		"high bit":             valid[:TextLen-1] + "\xff",
		"multibyte":            valid[:TextLen-2] + "é",
		"non canonical tail":   strings.Repeat("A", TextLen-1) + "B",
		"non canonical tail 3": strings.Repeat("A", TextLen-1) + "D",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := Hash(text); !errors.Is(err, ErrMalformed) || got != nil {
				t.Fatalf("Hash(%q) = %x, %v; want ErrMalformed", text, got, err)
			}
		})
	}
}

func TestHashAcceptsOnlyCanonicalTails(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := range len(alphabet) {
		text := strings.Repeat("A", TextLen-1) + string(alphabet[i])
		_, err := Hash(text)
		if canonical := i%4 == 0; canonical != (err == nil) {
			t.Errorf("Hash(%q) = %v, but the tail %q is canonical: %v", text, err, alphabet[i], canonical)
		}
	}
}

func TestEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"both nil", nil, nil, true},
		{"nil and empty", nil, []byte{}, true},
		{"same", []byte("abc"), []byte("abc"), true},
		{"different", []byte("abc"), []byte("abd"), false},
		{"prefix", []byte("abc"), []byte("abcd"), false},
		{"empty and one", []byte{}, []byte{0}, false},
	}
	for _, c := range cases {
		if got := Equal(c.a, c.b); got != c.want {
			t.Errorf("%s: Equal(%q, %q) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
}

func FuzzHash(f *testing.F) {
	f.Add("")
	f.Add(strings.Repeat("A", TextLen))
	f.Add(strings.Repeat("A", TextLen-1) + "B")
	f.Add(strings.Repeat("_", TextLen))
	f.Add(strings.Repeat("-", TextLen-1) + "Q")
	f.Add(strings.Repeat("A", TextLen-1) + "=")
	f.Add("é" + strings.Repeat("A", TextLen-2))
	f.Fuzz(func(t *testing.T, text string) {
		got, err := Hash(text)
		if err != nil {
			if !errors.Is(err, ErrMalformed) || got != nil {
				t.Fatalf("Hash(%q) = %x, %v; want ErrMalformed and no digest", text, got, err)
			}
			return
		}
		raw, decodeErr := encoding.DecodeString(text)
		if decodeErr != nil || len(raw) != Bytes || encoding.EncodeToString(raw) != text {
			t.Fatalf("Hash accepted %q, which is not the canonical text of %d bytes", text, Bytes)
		}
		if want := sha256.Sum256([]byte(text)); !bytes.Equal(got, want[:]) {
			t.Fatalf("Hash(%q) = %x, want %x", text, got, want)
		}
	})
}
