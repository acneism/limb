package password

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	DefaultMinLength = 12
	DefaultMaxLength = 128
	FloorMinLength   = 8
	CeilingMaxLength = 1024

	RuleMinLength = "min_length"
	RuleMaxLength = "max_length"
	RuleCommon    = "common_password"
	RuleLogin     = "login_identifier"
)

var ErrPolicy = errors.New("password: invalid policy")

type Policy struct {
	MinLength   int
	MaxLength   int
	AllowCommon bool
	AllowLogin  bool
	Custom      []func(ctx context.Context, password string) error
}

func DefaultPolicy() Policy {
	return Policy{MinLength: DefaultMinLength, MaxLength: DefaultMaxLength}
}

func (p Policy) WithDefaults() Policy {
	if p.MinLength == 0 {
		p.MinLength = DefaultMinLength
	}
	if p.MaxLength == 0 {
		p.MaxLength = DefaultMaxLength
	}
	return p
}

func (p Policy) Validate() error {
	switch {
	case p.MinLength < FloorMinLength:
		return fmt.Errorf("%w: minimum length must be at least %d", ErrPolicy, FloorMinLength)
	case p.MaxLength < p.MinLength:
		return fmt.Errorf("%w: maximum length must not be below the minimum length", ErrPolicy)
	case p.MaxLength > CeilingMaxLength:
		return fmt.Errorf("%w: maximum length must not exceed %d", ErrPolicy, CeilingMaxLength)
	}
	for _, check := range p.Custom {
		if check == nil {
			return fmt.Errorf("%w: custom check is nil", ErrPolicy)
		}
	}
	return nil
}

func (p Policy) Check(ctx context.Context, password string, logins []string) []string {
	normalized := Normalize(password)
	var rules []string
	length := utf8.RuneCountInString(normalized)
	if length < p.MinLength {
		rules = append(rules, RuleMinLength)
	}
	if length > p.MaxLength {
		rules = append(rules, RuleMaxLength)
	}
	if !p.AllowCommon && IsCommon(normalized) {
		rules = append(rules, RuleCommon)
	}
	if !p.AllowLogin && matchesAny(normalized, logins) {
		rules = append(rules, RuleLogin)
	}
	for _, check := range p.Custom {
		if err := check(ctx, normalized); err != nil {
			rules = append(rules, err.Error())
		}
	}
	return rules
}

func matchesAny(password string, logins []string) bool {
	for _, login := range logins {
		if login != "" && strings.EqualFold(password, Normalize(login)) {
			return true
		}
	}
	return false
}
