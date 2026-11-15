// Package identifier defines the kinds of values a user can sign in with or
// be reached at: e-mail addresses, nicknames, phone numbers and developer
// defined types. A Type validates and normalizes raw input into the single
// canonical form that limb stores and searches by.
package identifier

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxRawLength = 1024
	namePattern  = `^[a-z][a-z0-9_]{0,31}$`
)

var (
	nameRegexp = regexp.MustCompile(namePattern)

	errZeroType     = errors.New("identifier type is not initialized")
	errEmpty        = errors.New("value must not be empty")
	errTooLong      = errors.New("value is too long")
	errEncoding     = errors.New("value is not valid text")
	errNotCanonical = errors.New("value is not in canonical form")
	errPattern      = errors.New("value has an invalid format")
	errNoLoginType  = errors.New("no login type accepts the value")
)

type step func(string) (string, error)

type check func(string) error

// Type describes one kind of identifier. The zero Type is not usable; build
// values with Email, Username, Custom or the constructors of subpackages.
type Type struct {
	name     string
	login    bool
	delivery bool
	required bool
	steps    []step
	checks   []check
}

// Name returns the name of the type. It is stored with every value and is the
// key of the identifier in a registration.
func (t Type) Name() string {
	return t.name
}

// IsLogin reports whether users can sign in with values of this type.
func (t Type) IsLogin() bool {
	return t.login
}

// IsDelivery reports whether messages, such as links and codes, can be sent to
// values of this type.
func (t Type) IsDelivery() bool {
	return t.delivery
}

// IsRequired reports whether every user must have a value of this type.
func (t Type) IsRequired() bool {
	return t.required
}

// Normalize converts raw to the canonical form of the type and validates it.
// Input longer than 1024 bytes, text that is not valid UTF-8 and values with
// control characters are rejected. The result is a fixed point: normalizing it
// again returns the same value, and a value for which that does not hold is
// rejected.
func (t Type) Normalize(raw string) (string, error) {
	if t.name == "" {
		return "", errZeroType
	}
	if len(raw) > maxRawLength {
		return "", errTooLong
	}
	if !utf8.ValidString(raw) {
		return "", errEncoding
	}
	value, err := t.apply(raw)
	if err != nil {
		return "", err
	}
	again, err := t.apply(value)
	if err != nil || again != value {
		return "", errNotCanonical
	}
	return value, nil
}

func (t Type) apply(raw string) (string, error) {
	value := raw
	for _, run := range t.steps {
		next, err := run(value)
		if err != nil {
			return "", err
		}
		value = next
	}
	if value == "" {
		return "", errEmpty
	}
	if !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errEncoding
	}
	for _, verify := range t.checks {
		if err := verify(value); err != nil {
			return "", err
		}
	}
	return value, nil
}

func digitsOnly(value string) bool {
	return value != "" && strings.IndexFunc(value, func(r rune) bool { return !unicode.IsDigit(r) }) < 0
}

// Resolve finds the login type that accepts login. It tries the types that
// allow signing in in the order they are given and returns the first one
// whose Normalize accepts the value, together with the normalized value.
func Resolve(types []Type, login string) (Type, string, error) {
	for _, t := range types {
		if !t.login {
			continue
		}
		value, err := t.Normalize(login)
		if err == nil {
			return t, value, nil
		}
	}
	return Type{}, "", errNoLoginType
}
