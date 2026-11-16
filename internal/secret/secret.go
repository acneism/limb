package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	// Bytes is the number of random bytes in a secret, which is 256 bits.
	Bytes = 32
	// TextLen is the length of the text form of a secret.
	TextLen = 43
	// HashLen is the length of the hash of a secret.
	HashLen = sha256.Size
)

var (
	// ErrMalformed is returned for text that is not the canonical text form of
	// a secret.
	ErrMalformed = errors.New("secret: malformed secret")

	encoding = base64.RawURLEncoding.Strict()
)

// New returns a new random secret in its text form: 32 bytes from crypto/rand
// encoded as base64url without padding.
func New() (string, error) {
	return newFrom(rand.Reader)
}

func newFrom(r io.Reader) (string, error) {
	var raw [Bytes]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return "", fmt.Errorf("secret: random source failed: %w", err)
	}
	return encoding.EncodeToString(raw[:]), nil
}

// Hash returns the SHA-256 digest of the text form of a secret, which is what
// the database stores and is searched by. Anything that is not exactly the
// canonical text form of 32 bytes is rejected with ErrMalformed before it is
// hashed, so oversized or damaged input never reaches the database.
func Hash(text string) ([]byte, error) {
	if !wellFormed(text) {
		return nil, ErrMalformed
	}
	sum := sha256.Sum256([]byte(text))
	return sum[:], nil
}

func wellFormed(text string) bool {
	if len(text) != TextLen {
		return false
	}
	var raw [Bytes]byte
	n, err := encoding.Decode(raw[:], []byte(text))
	return err == nil && n == Bytes
}

// Equal compares two byte strings in constant time. It is the only way secrets
// are compared in memory.
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
