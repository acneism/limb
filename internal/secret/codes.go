package secret

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// CodeDigits is the number of digits of a code.
	CodeDigits = 6

	codeSpace      = 1_000_000
	codeLimit      = (1 << 32) / codeSpace * codeSpace
	codeDraws      = 64
	codeSeparators = " -"
)

// ErrNoCode is returned when the random source keeps giving values that cannot
// be turned into a code without bias, which a working source never does.
var ErrNoCode = errors.New("secret: the random source gave no usable value")

// CodeBinding names what a code is made for. The keyed hash of a code covers
// all of it, so a code works for one secret, one user, one purpose and one
// channel only.
type CodeBinding struct {
	TenantID     string
	ID           string
	UserID       string
	Purpose      string
	ChannelType  string
	ChannelValue string
}

// NewCode returns a code of CodeDigits decimal digits. Every one of the million
// codes is equally likely: a value is taken from the random source as 32 bits
// and thrown away if it falls in the last, incomplete block of the range, so the
// remainder is not biased.
func (k *Keys) NewCode() (string, error) {
	var raw [4]byte
	for range codeDraws {
		if _, err := io.ReadFull(k.random, raw[:]); err != nil {
			return "", fmt.Errorf("secret: random source failed: %w", err)
		}
		if n := binary.BigEndian.Uint32(raw[:]); n < codeLimit {
			return fmt.Sprintf("%0*d", CodeDigits, n%codeSpace), nil
		}
	}
	return "", ErrNoCode
}

// CodeHash returns the keyed hash of a code that is stored in its place: the
// HMAC-SHA256 of the binding and the code under a subkey of the master key. A
// code has only a million values, so a plain hash of it would give it away to
// whoever reads the database, and the key makes the stored value useless
// without the master key. The binding keeps a hash that was copied from one
// secret from working for another.
func (k *Keys) CodeHash(b CodeBinding, code string) []byte {
	return sum(k.codes, appendFramed(nil, []string{b.TenantID, b.ID, b.UserID, b.Purpose, b.ChannelType, b.ChannelValue, code}))
}

// CodeMatches reports whether the stored hash belongs to the code under the
// binding, comparing in constant time.
func (k *Keys) CodeMatches(stored []byte, b CodeBinding, code string) bool {
	return Equal(stored, k.CodeHash(b, code))
}

// ParseCode returns the canonical form of a code that a user typed: CodeDigits
// ASCII digits. Spaces around the code are ignored, and one space or hyphen is
// allowed between its two halves, as in 123 456 and 123-456. Everything else,
// including digits of other scripts, is refused.
func ParseCode(input string) (string, bool) {
	text := strings.TrimSpace(input)
	switch len(text) {
	case CodeDigits:
	case CodeDigits + 1:
		half := CodeDigits / 2
		if !strings.ContainsRune(codeSeparators, rune(text[half])) {
			return "", false
		}
		text = text[:half] + text[half+1:]
	default:
		return "", false
	}
	for i := range len(text) {
		if text[i] < '0' || text[i] > '9' {
			return "", false
		}
	}
	return text, true
}
