package password

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.MinLength != 12 || p.MaxLength != 128 || p.AllowCommon || p.AllowLogin || len(p.Custom) != 0 {
		t.Fatalf("unexpected defaults: %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("the default policy must be valid: %v", err)
	}
}

func TestPolicyWithDefaults(t *testing.T) {
	got := Policy{}.WithDefaults()
	if got.MinLength != DefaultMinLength || got.MaxLength != DefaultMaxLength {
		t.Fatalf("zero values must become the defaults, got %+v", got)
	}
	kept := Policy{MinLength: 9, MaxLength: 70}.WithDefaults()
	if kept.MinLength != 9 || kept.MaxLength != 70 {
		t.Fatalf("explicit values must be kept, got %+v", kept)
	}
}

func TestPolicyValidate(t *testing.T) {
	valid := []Policy{
		{MinLength: 8, MaxLength: 8},
		{MinLength: 12, MaxLength: 128},
		{MinLength: 15, MaxLength: 1024},
	}
	for _, p := range valid {
		if err := p.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", p, err)
		}
	}
	invalid := map[string]Policy{
		"minimum below the floor": {MinLength: 7, MaxLength: 128},
		"zero minimum":            {MinLength: 0, MaxLength: 128},
		"maximum below minimum":   {MinLength: 12, MaxLength: 11},
		"maximum above ceiling":   {MinLength: 12, MaxLength: 1025},
		"nil custom check":        {MinLength: 12, MaxLength: 128, Custom: []func(context.Context, string) error{nil}},
	}
	for name, p := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate(); !errors.Is(err, ErrPolicy) {
				t.Fatalf("Validate(%+v) = %v, want ErrPolicy", p, err)
			}
		})
	}
}

func TestPolicyLength(t *testing.T) {
	p := DefaultPolicy()
	p.AllowCommon = true
	cases := []struct {
		name     string
		password string
		want     []string
	}{
		{"one below the minimum", strings.Repeat("a", 11), []string{RuleMinLength}},
		{"the minimum", strings.Repeat("a", 12), nil},
		{"the maximum", strings.Repeat("a", 128), nil},
		{"one above the maximum", strings.Repeat("a", 129), []string{RuleMaxLength}},
		{"empty", "", []string{RuleMinLength}},
		{"counts characters, not bytes", strings.Repeat("я", 12), nil},
		{"counts characters, not bytes at the maximum", strings.Repeat("я", 128), nil},
		{"counted after NFKC", strings.Repeat("ﬁ", 6), nil},
		{"short before and after NFKC", strings.Repeat("ﬁ", 5), []string{RuleMinLength}},
		{"long after NFKC", strings.Repeat("ﬁ", 65), []string{RuleMaxLength}},
		{"no composition rules", "                ", nil},
		{"only digits", "840217396518", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Check(t.Context(), tc.password, nil)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Check(%q) = %v, want %v", tc.password, got, tc.want)
			}
		})
	}
}

func TestPolicyCustomLimits(t *testing.T) {
	p := Policy{MinLength: 8, MaxLength: 10}
	if got := p.Check(t.Context(), "zx7q9wk2", nil); got != nil {
		t.Fatalf("got %v", got)
	}
	if got := p.Check(t.Context(), "zx7q9wk2mnb", nil); !reflect.DeepEqual(got, []string{RuleMaxLength}) {
		t.Fatalf("got %v", got)
	}
}

func TestPolicyRejectsLoginIdentifiers(t *testing.T) {
	p := DefaultPolicy()
	logins := []string{"alice@example.com", "Alice@Example.com", "alice_wonder_01", "+79261234567", ""}
	cases := []struct {
		name     string
		password string
		want     []string
	}{
		{"normalized e-mail", "alice@example.com", []string{RuleLogin}},
		{"e-mail in other case", "ALICE@EXAMPLE.COM", []string{RuleLogin}},
		{"nickname", "Alice_Wonder_01", []string{RuleLogin}},
		{"phone number", "+79261234567", []string{RuleLogin}},
		{"compatibility form of the login", "ａｌｉｃｅ＿ｗｏｎｄｅｒ＿０１", []string{RuleLogin}},
		{"login with a suffix", "alice@example.com1", nil},
		{"unrelated password", "correct horse battery", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Check(t.Context(), tc.password, logins); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Check(%q) = %v, want %v", tc.password, got, tc.want)
			}
		})
	}
	allowed := DefaultPolicy()
	allowed.AllowLogin = true
	if got := allowed.Check(t.Context(), "alice@example.com", logins); got != nil {
		t.Fatalf("AllowLogin must disable the rule, got %v", got)
	}
}

func TestPolicyRejectsCommonPasswords(t *testing.T) {
	p := Policy{MinLength: 8, MaxLength: 128}
	cases := []struct {
		name     string
		password string
		want     []string
	}{
		{"listed", "unbelievable", []string{RuleCommon}},
		{"listed in other case", "UnBelievable", []string{RuleCommon}},
		{"listed in compatibility form", "ｕｎｂｅｌｉｅｖａｂｌｅ", []string{RuleCommon}},
		{"not listed", "unbelievable-horse", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Check(t.Context(), tc.password, nil); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Check(%q) = %v, want %v", tc.password, got, tc.want)
			}
		})
	}
	p.AllowCommon = true
	if got := p.Check(t.Context(), "unbelievable", nil); got != nil {
		t.Fatalf("AllowCommon must disable the rule, got %v", got)
	}
}

func TestPolicyRunsCustomChecksOnTheNormalizedPassword(t *testing.T) {
	var seen []string
	p := DefaultPolicy()
	p.Custom = []func(context.Context, string) error{
		func(_ context.Context, password string) error {
			seen = append(seen, password)
			if strings.Contains(password, "leaked") {
				return errors.New("found in a breach database")
			}
			return nil
		},
		func(context.Context, string) error { return nil },
	}
	got := p.Check(t.Context(), "ｌｅａｋｅｄ-password-1", nil)
	if !reflect.DeepEqual(got, []string{"found in a breach database"}) {
		t.Fatalf("got %v", got)
	}
	if len(seen) != 1 || seen[0] != "leaked-password-1" {
		t.Fatalf("custom check must see the NFKC form, saw %q", seen)
	}
	if got = p.Check(t.Context(), "an unremarkable passphrase", nil); got != nil {
		t.Fatalf("got %v", got)
	}
}

func TestPolicyPassesContextToCustomChecks(t *testing.T) {
	type key struct{}
	ctx := context.WithValue(t.Context(), key{}, "value")
	var got any
	p := DefaultPolicy()
	p.Custom = []func(context.Context, string) error{func(c context.Context, _ string) error {
		got = c.Value(key{})
		return nil
	}}
	p.Check(ctx, "an unremarkable passphrase", nil)
	if got != "value" {
		t.Fatalf("custom check did not receive the caller's context, got %v", got)
	}
}

func TestPolicyReportsEveryViolatedRule(t *testing.T) {
	p := Policy{MinLength: 12, MaxLength: 128, Custom: []func(context.Context, string) error{
		func(context.Context, string) error { return errors.New("custom rule") },
	}}
	got := p.Check(t.Context(), "password", []string{"password"})
	want := []string{RuleMinLength, RuleCommon, RuleLogin, "custom rule"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func FuzzPolicy(f *testing.F) {
	for _, seed := range []string{"", "a", "password", "unbelievable", "alice@example.com", "ﬁﬁﬁﬁﬁﬁ", "\x00\xff", strings.Repeat("я", 200)} {
		f.Add(seed, "Alice@Example.com")
	}
	p := DefaultPolicy()
	f.Fuzz(func(t *testing.T, password, login string) {
		rules := p.Check(t.Context(), password, []string{login})
		length := utf8.RuneCountInString(Normalize(password))
		withinBounds := length >= p.MinLength && length <= p.MaxLength
		hasLengthRule := false
		for _, rule := range rules {
			if rule == RuleMinLength || rule == RuleMaxLength {
				hasLengthRule = true
			}
		}
		if withinBounds == hasLengthRule {
			t.Fatalf("length %d: within bounds=%v but rules=%v", length, withinBounds, rules)
		}
		if login != "" && strings.EqualFold(Normalize(password), Normalize(login)) && !contains(rules, RuleLogin) {
			t.Fatalf("a password equal to the login passed: %q %q", password, login)
		}
	})
}

func contains(rules []string, rule string) bool {
	for _, r := range rules {
		if r == rule {
			return true
		}
	}
	return false
}
