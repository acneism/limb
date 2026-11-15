package identifier

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

type settings struct {
	login      bool
	delivery   bool
	required   bool
	minLength  int
	maxLength  int
	pattern    *regexp.Regexp
	steps      []step
	validators []check
	err        error
}

func (s *settings) fail(err error) {
	if s.err == nil {
		s.err = err
	}
}

// Option customizes an identifier Type. An option that is given an invalid
// argument does not panic: the first such error is kept by the Type and is
// reported by Type.Err and by Type.Normalize.
type Option func(*settings)

// Required makes the type mandatory: every user must have a value of it.
func Required() Option {
	return func(s *settings) {
		s.required = true
	}
}

// LoginAllowed lets users sign in with values of the type.
func LoginAllowed() Option {
	return func(s *settings) {
		s.login = true
	}
}

// Delivery marks the type as a delivery channel: messages, such as links and
// codes, can be sent to its values.
func Delivery() Option {
	return func(s *settings) {
		s.delivery = true
	}
}

// Pattern requires the whole normalized value to match the regular expression
// expr. It replaces any pattern the type has by default. An expression that
// does not compile makes Type.Err report an error.
func Pattern(expr string) Option {
	anchored, err := compileAnchored(expr)
	return func(s *settings) {
		if err != nil {
			s.fail(fmt.Errorf("invalid pattern %q: %w", expr, err))
			return
		}
		s.pattern = anchored
	}
}

func compileAnchored(expr string) (*regexp.Regexp, error) {
	if _, err := regexp.Compile(expr); err != nil {
		return nil, err
	}
	return regexp.Compile("^(?:" + expr + ")$")
}

// Length requires the normalized value to be between minChars and maxChars
// characters long, both inclusive. It replaces any length limits the type has
// by default. A negative minChars, a maxChars below one or a maxChars below
// minChars makes Type.Err report an error.
func Length(minChars, maxChars int) Option {
	return func(s *settings) {
		if minChars < 0 || maxChars < 1 || maxChars < minChars {
			s.fail(fmt.Errorf("invalid length range %d..%d", minChars, maxChars))
			return
		}
		s.minLength = minChars
		s.maxLength = maxChars
	}
}

// Validate adds a check that runs on the normalized value. A non-nil error
// rejects the value and its text is reported as the reason. A nil fn makes
// Type.Err report an error.
func Validate(fn func(string) error) Option {
	return func(s *settings) {
		if fn == nil {
			s.fail(errors.New("the function given to Validate is nil"))
			return
		}
		s.validators = append(s.validators, fn)
	}
}

// Normalize adds a normalization step that runs after the built-in ones of the
// type, in the order the options are given. The function returns the converted
// value or an error that rejects the input. A nil fn makes Type.Err report an
// error.
func Normalize(fn func(string) (string, error)) Option {
	return func(s *settings) {
		if fn == nil {
			s.fail(errors.New("the function given to Normalize is nil"))
			return
		}
		s.steps = append(s.steps, fn)
	}
}

// Invalid makes Type.Err report err. It is meant for constructors that
// validate their own arguments, such as the ones in subpackages, so that a bad
// configuration is returned as an error instead of causing a panic. A nil err
// changes nothing.
func Invalid(err error) Option {
	return func(s *settings) {
		if err != nil {
			s.fail(err)
		}
	}
}

type spec struct {
	name     string
	base     step
	rules    []check
	defaults settings
	err      error
}

func build(sp spec, opts []Option) Type {
	cfg := sp.defaults
	cfg.err = sp.err
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	t := Type{
		name:     sp.name,
		login:    cfg.login,
		delivery: cfg.delivery,
		required: cfg.required,
		err:      cfg.err,
		steps:    make([]step, 0, len(cfg.steps)+1),
		checks:   append([]check(nil), sp.rules...),
	}
	if sp.base != nil {
		t.steps = append(t.steps, sp.base)
	}
	t.steps = append(t.steps, cfg.steps...)
	if cfg.maxLength > 0 {
		t.checks = append(t.checks, lengthCheck(cfg.minLength, cfg.maxLength))
	}
	if cfg.pattern != nil {
		t.checks = append(t.checks, patternCheck(cfg.pattern))
	}
	t.checks = append(t.checks, cfg.validators...)
	return t
}

func lengthCheck(minChars, maxChars int) check {
	return func(value string) error {
		n := utf8.RuneCountInString(value)
		switch {
		case n < minChars:
			return fmt.Errorf("value is too short: at least %d characters required", minChars)
		case n > maxChars:
			return fmt.Errorf("value is too long: at most %d characters allowed", maxChars)
		}
		return nil
	}
}

func patternCheck(re *regexp.Regexp) check {
	return func(value string) error {
		if !re.MatchString(value) {
			return errPattern
		}
		return nil
	}
}

// Custom creates a type with the given name. The name starts with a lower case
// letter, continues with lower case letters, digits and underscores, and is at
// most 32 characters long; any other name makes Type.Err report an error.
// Surrounding white space is removed from values; add more rules with Pattern,
// Length, Validate and Normalize. A custom type is neither a login nor a
// delivery type unless LoginAllowed or Delivery says so.
func Custom(name string, opts ...Option) Type {
	sp := spec{name: name, base: trimSpace}
	if !nameRegexp.MatchString(name) {
		sp.err = fmt.Errorf("invalid type name %q", name)
	}
	return build(sp, opts)
}

func trimSpace(value string) (string, error) {
	return strings.TrimSpace(value), nil
}
