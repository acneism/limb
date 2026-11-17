package secret

import (
	"fmt"
	"io"
	"strings"
)

const (
	// RecoveryCodeLength is the number of characters of a recovery code, in the
	// canonical form without hyphens: 25 characters of 5 bits, 125 bits.
	RecoveryCodeLength = 25

	recoveryAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	recoveryGroup    = 5
	maxRecoveryInput = 64
)

// NewRecoveryCode returns a recovery code in the canonical form: RecoveryCodeLength
// characters from A to Z and 2 to 7. Every character takes the low five bits of a
// random byte, and 256 is a multiple of 32, so all the characters are equally
// likely. With 125 bits the code is far beyond what can be guessed, and a keyed
// hash of it is enough to keep in the database.
func (k *Keys) NewRecoveryCode() (string, error) {
	raw := make([]byte, RecoveryCodeLength)
	if _, err := io.ReadFull(k.random, raw); err != nil {
		return "", fmt.Errorf("secret: random source failed: %w", err)
	}
	var code strings.Builder
	for _, b := range raw {
		code.WriteByte(recoveryAlphabet[b&31])
	}
	return code.String(), nil
}

// FormatRecoveryCode writes a code in the canonical form in groups of five
// characters with hyphens, which is easier to read and to copy by hand.
func FormatRecoveryCode(code string) string {
	var out strings.Builder
	for i := 0; i < len(code); i += recoveryGroup {
		if i > 0 {
			out.WriteByte('-')
		}
		out.WriteString(code[i:min(i+recoveryGroup, len(code))])
	}
	return out.String()
}

// ParseRecoveryCode returns the canonical form of a recovery code that a person
// typed: the characters in upper case without the hyphens and the spaces. It
// refuses input that is not exactly RecoveryCodeLength characters of the
// alphabet after that.
func ParseRecoveryCode(input string) (string, bool) {
	if len(input) > maxRecoveryInput {
		return "", false
	}
	var code strings.Builder
	for i := range len(input) {
		c := input[i]
		switch {
		case c == '-' || c == ' ':
		case c >= 'a' && c <= 'z':
			code.WriteByte(c - 'a' + 'A')
		case strings.IndexByte(recoveryAlphabet, c) >= 0:
			code.WriteByte(c)
		default:
			return "", false
		}
	}
	if code.Len() != RecoveryCodeLength {
		return "", false
	}
	return code.String(), true
}

// RecoveryHash returns the keyed hash of a recovery code in the canonical form
// that is stored in its place: the HMAC-SHA256 of the ID of the administrator and
// the code under a subkey of the master key. The ID keeps a hash that was copied
// from one administrator to another from working.
func (k *Keys) RecoveryHash(adminID, code string) []byte {
	return sum(k.recovery, appendFramed(nil, []string{adminID, code}))
}
