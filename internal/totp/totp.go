// Package totp makes and checks the time-based one-time passwords of RFC 6238
// that an authenticator application shows: HMAC-SHA1, six digits and a step of
// 30 seconds. A password is accepted a step before and a step after the one of the
// server, which is the allowance for the clocks of the two. That a password works
// once is not this package's to enforce: Verify returns the step that matched,
// and whoever stores the last accepted step refuses a step that is not greater.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/acneism/limb/internal/secret"
)

const (
	// Digits is the number of digits of a password.
	Digits = 6

	// StepSeconds is the length of a time step.
	StepSeconds = 30

	// Window is how many steps before and after the current one are accepted.
	Window = 1

	// SecretLength is the length in bytes of the seed: 160 bits, as RFC 4226
	// recommends.
	SecretLength = 20
)

var (
	powersOfTen = [...]uint32{1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000}
	encoding    = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// NewSecret returns a seed of SecretLength random bytes.
func NewSecret() ([]byte, error) {
	return newSecret(rand.Reader)
}

func newSecret(random io.Reader) ([]byte, error) {
	seed := make([]byte, SecretLength)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, fmt.Errorf("totp: random source failed: %w", err)
	}
	return seed, nil
}

// EncodeSecret returns the seed in base32 without padding, as an authenticator
// application takes it when the key is typed by hand.
func EncodeSecret(seed []byte) string {
	return encoding.EncodeToString(seed)
}

// Step returns the time step that the moment falls in. The moments before 1970
// are in the step 0.
func Step(t time.Time) int64 {
	return max(0, t.Unix()) / StepSeconds
}

// Code returns the password for the time step.
func Code(seed []byte, step int64) string {
	return hotp(seed, uint64(max(0, step)), Digits)
}

func hotp(seed []byte, counter uint64, digits int) string {
	mac := hmac.New(sha1.New, seed)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, truncated%powersOfTen[digits])
}

// Verify checks the password that was typed against the seed at the moment now.
// It returns the step that the password belongs to, and whether there is one. A
// password may be typed with a space or a hyphen between its halves. Every step
// of the window is computed and compared whatever the input is, so the time that
// it takes does not tell which step matched. When the same password fits two
// steps, which happens once in a million, the later one is returned.
func Verify(seed []byte, input string, now time.Time) (int64, bool) {
	typed, ok := secret.ParseCode(input)
	if !ok || len(seed) == 0 {
		return 0, false
	}
	current := Step(now)
	matched := int64(-1)
	for step := current - Window; step <= current+Window; step++ {
		if step < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(Code(seed, step)), []byte(typed)) == 1 {
			matched = step
		}
	}
	return matched, matched >= 0
}

// URI returns the address that an authenticator application takes from a QR code
// to add the account: the seed, the issuer that is shown with the account and
// the account name. A colon of the issuer is replaced by a space, because the
// format of the address uses the colon to tell the issuer from the account.
func URI(issuer, account string, seed []byte) string {
	issuer = strings.ReplaceAll(issuer, ":", " ")
	account = strings.ReplaceAll(account, ":", " ")
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	query := url.Values{}
	query.Set("secret", EncodeSecret(seed))
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", strconv.Itoa(Digits))
	query.Set("period", strconv.Itoa(StepSeconds))
	return "otpauth://totp/" + label + "?" + query.Encode()
}
