package identifier

import (
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
}

// Option customizes an identifier Type.
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
// expr. It replaces any pattern the type has by default. Pattern panics if
// expr is not a valid regular expression.
func Pattern(expr string) Option {
	compiled, err := regexp.Compile("^(?:" + expr + ")$")
	if err != nil {
		panic(fmt.Sprintf("identifier: invalid pattern %q: %v", expr, err))
	}
	return func(s *settings) {
		s.pattern = compiled
	}
}

// Length requires the normalized value to be between minChars and maxChars
// characters long, both inclusive. It replaces any length limits the type has
// by default. Length panics if minChars is negative or maxChars is smaller than
// minChars or than one.
func Length(minChars, maxChars int) Option {
	if minChars < 0 || maxChars < 1 || maxChars < minChars {
		panic(fmt.Sprintf("identifier: invalid length range %d..%d", minChars, maxChars))
	}
	return func(s *settings) {
		s.minLength = minChars
		s.maxLength = maxChars
	}
}

// Validate adds a check that runs on the normalized value. A non-nil error
// rejects the value and its text is reported as the reason. Validate panics if
// fn is nil.
func Validate(fn func(string) error) Option {
	if fn == nil {
		panic("identifier: Validate requires a function")
	}
	return func(s *settings) {
		s.validators = append(s.validators, fn)
	}
}

// Normalize adds a normalization step that runs after the built-in ones of the
// type, in the order the options are given. The function returns the converted
// value or an error that rejects the input. Normalize panics if fn is nil.
func Normalize(fn func(string) (string, error)) Option {
	if fn == nil {
		panic("identifier: Normalize requires a function")
	}
	return func(s *settings) {
		s.steps = append(s.steps, fn)
	}
}

type spec struct {
	name     string
	base     step
	rules    []check
	defaults settings
}

func build(sp spec, opts []Option) Type {
	cfg := sp.defaults
	for _, opt := range opts {
		opt(&cfg)
	}
	t := Type{
		name:     sp.name,
		login:    cfg.login,
		delivery: cfg.delivery,
		required: cfg.required,
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
// most 32 characters long; Custom panics otherwise. Surrounding white space is
// removed from values; add more rules with Pattern, Length, Validate and
// Normalize. A custom type is neither a login nor a delivery type unless
// LoginAllowed or Delivery says so.
func Custom(name string, opts ...Option) Type {
	if !nameRegexp.MatchString(name) {
		panic(fmt.Sprintf("identifier: invalid type name %q", name))
	}
	return build(spec{name: name, base: trimSpace}, opts)
}

func trimSpace(value string) (string, error) {
	return strings.TrimSpace(value), nil
}
