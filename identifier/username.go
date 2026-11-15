package identifier

import (
	"errors"
	"regexp"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const (
	usernameTypeName  = "username"
	usernameMinLength = 3
	usernameMaxLength = 32
	foldPasses        = 4

	cherokeeCapitalStart      = 0x13A0
	cherokeeSmallStart        = 0xAB70
	cherokeeSmallEnd          = 0xABBF
	cherokeeCapitalExtraStart = 0x13F0
	cherokeeSmallExtraStart   = 0x13F8
	cherokeeSmallExtraEnd     = 0x13FD
)

var (
	usernamePattern = regexp.MustCompile(`^[a-z0-9_.-]+$`)

	errUsernameAt     = errors.New("nickname must not contain @")
	errUsernamePlus   = errors.New("nickname must not start with +")
	errUsernameDigits = errors.New("nickname must not consist of digits only")
)

// Username returns the nickname type. Users can sign in with it but messages
// cannot be sent to it. Values are trimmed, converted with Unicode NFKC and
// case folded, so comparison ignores case. By default a nickname is 3 to 32
// characters long and made of a-z, 0-9, underscore, dot and hyphen; Length and
// Pattern replace these defaults. A nickname never contains @, never starts
// with + and never consists of digits only, whatever the options say, so
// that it cannot be mistaken for an e-mail address or a phone number.
func Username(opts ...Option) Type {
	return build(spec{
		name:  usernameTypeName,
		base:  normalizeUsername,
		rules: []check{usernameFormat},
		defaults: settings{
			login:     true,
			minLength: usernameMinLength,
			maxLength: usernameMaxLength,
			pattern:   usernamePattern,
		},
	}, opts)
}

func normalizeUsername(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	for range foldPasses {
		next := strings.TrimSpace(foldOnce(value))
		if next == value {
			break
		}
		value = next
	}
	return value, nil
}

func foldOnce(value string) string {
	value = norm.NFKC.String(value)
	value = cases.Fold().String(value)
	value = strings.Map(cherokeeCapital, value)
	return norm.NFKC.String(value)
}

func cherokeeCapital(r rune) rune {
	switch {
	case r >= cherokeeSmallStart && r <= cherokeeSmallEnd:
		return r - cherokeeSmallStart + cherokeeCapitalStart
	case r >= cherokeeSmallExtraStart && r <= cherokeeSmallExtraEnd:
		return r - cherokeeSmallExtraStart + cherokeeCapitalExtraStart
	}
	return r
}

func usernameFormat(value string) error {
	switch {
	case strings.Contains(value, "@"):
		return errUsernameAt
	case strings.HasPrefix(value, "+"):
		return errUsernamePlus
	case digitsOnly(value):
		return errUsernameDigits
	}
	return nil
}
