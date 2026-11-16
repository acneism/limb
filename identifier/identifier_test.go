package identifier_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/acneism/limb/identifier"
)

type normalizeCase struct {
	name string
	raw  string
	want string
	fail bool
}

func runNormalizeCases(t *testing.T, typ identifier.Type, cases []normalizeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := typ.Normalize(tc.raw)
			if tc.fail {
				if err == nil {
					t.Fatalf("Normalize(%q) = %q, want an error", tc.raw, got)
				}
				if got != "" {
					t.Fatalf("Normalize(%q) returned %q together with an error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%q) failed: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("Normalize(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestEmailNormalize(t *testing.T) {
	longLabels := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63)
	runNormalizeCases(t, identifier.Email(), []normalizeCase{
		{name: "plain", raw: "alice@example.com", want: "alice@example.com"},
		{name: "trim and lower case", raw: "  Alice@Example.COM \t", want: "alice@example.com"},
		{name: "plus tag", raw: "alice+news@mail.example.co.uk", want: "alice+news@mail.example.co.uk"},
		{name: "specials in local part", raw: "a.b_c-d!e#f@example.org", want: "a.b_c-d!e#f@example.org"},
		{name: "idn domain", raw: "user@пример.рф", want: "user@xn--e1afmkfd.xn--p1ai"},
		{name: "idn domain upper case", raw: "User@ПРИМЕР.РФ", want: "user@xn--e1afmkfd.xn--p1ai"},
		{name: "punycode domain", raw: "user@xn--e1afmkfd.xn--p1ai", want: "user@xn--e1afmkfd.xn--p1ai"},
		{name: "fullwidth domain", raw: "user@ｅｘａｍｐｌｅ.ｃｏｍ", want: "user@example.com"},
		{name: "empty", raw: "", fail: true},
		{name: "blank", raw: "   ", fail: true},
		{name: "no at sign", raw: "alice.example.com", fail: true},
		{name: "two at signs", raw: "a@b@example.com", fail: true},
		{name: "display name", raw: "Alice <alice@example.com>", fail: true},
		{name: "angle brackets only", raw: "<alice@example.com>", fail: true},
		{name: "empty local part", raw: "@example.com", fail: true},
		{name: "empty domain", raw: "alice@", fail: true},
		{name: "domain without dot", raw: "alice@localhost", fail: true},
		{name: "domain with trailing dot", raw: "alice@example.com.", fail: true},
		{name: "numeric top level domain", raw: "alice@192.168.0.1", fail: true},
		{name: "domain literal", raw: "alice@[192.168.0.1]", fail: true},
		{name: "underscore in domain", raw: "alice@exa_mple.com", fail: true},
		{name: "leading hyphen in label", raw: "alice@-example.com", fail: true},
		{name: "empty label", raw: "alice@example..com", fail: true},
		{name: "label too long", raw: "alice@" + strings.Repeat("a", 64) + ".com", fail: true},
		{name: "non ascii local part", raw: "пользователь@example.com", fail: true},
		{name: "space in local part", raw: "al ice@example.com", fail: true},
		{name: "quoted local part", raw: `"alice"@example.com`, fail: true},
		{name: "leading dot", raw: ".alice@example.com", fail: true},
		{name: "trailing dot", raw: "alice.@example.com", fail: true},
		{name: "double dot", raw: "al..ice@example.com", fail: true},
		{name: "local part of 64", raw: strings.Repeat("a", 64) + "@example.com", want: strings.Repeat("a", 64) + "@example.com"},
		{name: "local part of 65", raw: strings.Repeat("a", 65) + "@example.com", fail: true},
		{name: "address longer than 254", raw: strings.Repeat("a", 64) + "@" + longLabels, fail: true},
		{name: "address of 254", raw: strings.Repeat("a", 64) + "@" + longLabels[:189], want: strings.Repeat("a", 64) + "@" + longLabels[:189]},
		{name: "control character", raw: "alice\x00@example.com", fail: true},
		{name: "invalid utf-8", raw: "alice@exam\xffple.com", fail: true},
		{name: "raw longer than limit", raw: strings.Repeat("a", 2000) + "@example.com", fail: true},
	})
}

func TestUsernameNormalize(t *testing.T) {
	runNormalizeCases(t, identifier.Username(), []normalizeCase{
		{name: "plain", raw: "alice", want: "alice"},
		{name: "case folded", raw: "Alice_01", want: "alice_01"},
		{name: "trimmed", raw: "  bob.smith  ", want: "bob.smith"},
		{name: "fullwidth", raw: "ＢＯＢ", want: "bob"},
		{name: "ligature", raw: "ﬁsh", want: "fish"},
		{name: "hyphen and digits", raw: "a-1", want: "a-1"},
		{name: "minimum length", raw: "abc", want: "abc"},
		{name: "maximum length", raw: strings.Repeat("a", 32), want: strings.Repeat("a", 32)},
		{name: "too short", raw: "ab", fail: true},
		{name: "too long", raw: strings.Repeat("a", 33), fail: true},
		{name: "empty", raw: "", fail: true},
		{name: "digits only", raw: "123456", fail: true},
		{name: "fullwidth digits only", raw: "１２３４", fail: true},
		{name: "starts with plus", raw: "+alice", fail: true},
		{name: "contains at sign", raw: "alice@x", fail: true},
		{name: "space inside", raw: "alice smith", fail: true},
		{name: "outside default alphabet", raw: "älice", fail: true},
		{name: "control character", raw: "ali\x07ce", fail: true},
	})
}

func TestUsernameOptionsReplaceDefaults(t *testing.T) {
	runNormalizeCases(t, identifier.Username(identifier.Length(2, 6), identifier.Pattern(`[\p{L}\d]+`)), []normalizeCase{
		{name: "short", raw: "Ян", want: "ян"},
		{name: "non latin", raw: "Ärger", want: "ärger"},
		{name: "too long", raw: "abcdefg", fail: true},
		{name: "hyphen no longer allowed", raw: "a-b", fail: true},
		{name: "digits only still rejected", raw: "12345", fail: true},
		{name: "plus still rejected", raw: "+abc", fail: true},
	})
}

func TestUsernameFoldsCherokeeToCapitals(t *testing.T) {
	runNormalizeCases(t, identifier.Username(identifier.Pattern(`.+`), identifier.Length(1, 40)), []normalizeCase{
		{name: "small letter", raw: "ꭾ", want: "Ꭾ"},
		{name: "capital letter", raw: "Ꭾ", want: "Ꭾ"},
		{name: "extra small letter", raw: "ᏸ", want: "Ᏸ"},
		{name: "extra capital letter", raw: "Ᏸ", want: "Ᏸ"},
	})
}

func TestUsernameHardRulesSurviveAnyPattern(t *testing.T) {
	typ := identifier.Username(identifier.Pattern(`.+`), identifier.Length(1, 40))
	for _, raw := range []string{"a@b", "+1", "42"} {
		if got, err := typ.Normalize(raw); err == nil {
			t.Fatalf("Normalize(%q) = %q, want an error", raw, got)
		}
	}
}

func TestCustomType(t *testing.T) {
	typ := identifier.Custom("employee_id", identifier.Pattern(`[0-9]{6}`), identifier.LoginAllowed(), identifier.Required())
	if typ.Name() != "employee_id" || !typ.IsLogin() || typ.IsDelivery() || !typ.IsRequired() {
		t.Fatalf("unexpected flags: name=%q login=%v delivery=%v required=%v", typ.Name(), typ.IsLogin(), typ.IsDelivery(), typ.IsRequired())
	}
	runNormalizeCases(t, typ, []normalizeCase{
		{name: "valid", raw: "123456", want: "123456"},
		{name: "trimmed", raw: " 123456\n", want: "123456"},
		{name: "too short", raw: "12345", fail: true},
		{name: "too long", raw: "1234567", fail: true},
		{name: "pattern is anchored at the start", raw: "x123456", fail: true},
		{name: "pattern is anchored at the end", raw: "123456x", fail: true},
		{name: "empty", raw: "", fail: true},
		{name: "blank", raw: "  ", fail: true},
	})
}

func TestCustomTypeDefaults(t *testing.T) {
	typ := identifier.Custom("badge")
	if typ.IsLogin() || typ.IsDelivery() || typ.IsRequired() {
		t.Fatalf("a bare custom type must have no flags: login=%v delivery=%v required=%v", typ.IsLogin(), typ.IsDelivery(), typ.IsRequired())
	}
	delivery := identifier.Custom("pager", identifier.Delivery())
	if !delivery.IsDelivery() || delivery.IsLogin() {
		t.Fatalf("Delivery option not applied: login=%v delivery=%v", delivery.IsLogin(), delivery.IsDelivery())
	}
}

func TestCustomTypeNormalizeAndValidate(t *testing.T) {
	typ := identifier.Custom("code",
		identifier.Normalize(func(s string) (string, error) { return strings.ToUpper(s), nil }),
		identifier.Normalize(func(s string) (string, error) { return strings.ReplaceAll(s, "-", ""), nil }),
		identifier.Validate(func(s string) error {
			if strings.HasPrefix(s, "X") {
				return errors.New("prefix X is reserved")
			}
			return nil
		}),
		identifier.Length(3, 6),
	)
	runNormalizeCases(t, typ, []normalizeCase{
		{name: "steps run in order", raw: " ab-c1 ", want: "ABC1"},
		{name: "validator rejects", raw: "x-yz", fail: true},
		{name: "length rejects after normalization", raw: "a-b", fail: true},
		{name: "length upper bound", raw: "abcdefg", fail: true},
	})
	_, err := typ.Normalize("x-yz")
	if err == nil || err.Error() != "prefix X is reserved" {
		t.Fatalf("validator error must be reported as is, got %v", err)
	}
}

func TestNormalizeHasLengthLimitsInBytes(t *testing.T) {
	typ := identifier.Custom("badge")
	cases := []normalizeCase{
		{name: "the longest value", raw: strings.Repeat("a", identifier.MaxValueLength), want: strings.Repeat("a", identifier.MaxValueLength)},
		{name: "the longest value in two byte characters", raw: strings.Repeat("é", identifier.MaxValueLength/2), want: strings.Repeat("é", identifier.MaxValueLength/2)},
		{name: "the longest value in four byte characters", raw: strings.Repeat("\U0001F600", identifier.MaxValueLength/4), want: strings.Repeat("\U0001F600", identifier.MaxValueLength/4)},
		{name: "one byte over", raw: strings.Repeat("a", identifier.MaxValueLength+1), fail: true},
		{name: "two byte characters over", raw: strings.Repeat("é", identifier.MaxValueLength/2+1), fail: true},
		{name: "four byte characters over", raw: strings.Repeat("\U0001F600", identifier.MaxValueLength/4+1), fail: true},
		{name: "the longest input", raw: strings.Repeat("a", identifier.MaxInputLength), fail: true},
		{name: "one byte over the longest input", raw: strings.Repeat("a", identifier.MaxInputLength+1), fail: true},
	}
	runNormalizeCases(t, typ, cases)
	for _, raw := range []string{
		strings.Repeat("a", identifier.MaxValueLength+1),
		strings.Repeat("a", identifier.MaxInputLength),
		strings.Repeat("a", identifier.MaxInputLength+1),
	} {
		if _, err := typ.Normalize(raw); err == nil || err.Error() != "value is too long" {
			t.Errorf("Normalize of %d bytes: %v, want the error about the length", len(raw), err)
		}
	}
}

func TestNormalizeLimitsTheValueNotTheInput(t *testing.T) {
	typ := identifier.Custom("badge", identifier.Normalize(func(s string) (string, error) { return strings.TrimSpace(s), nil }))
	padded := strings.Repeat(" ", 400) + strings.Repeat("a", identifier.MaxValueLength) + strings.Repeat(" ", 100)
	if len(padded) > identifier.MaxInputLength {
		t.Fatalf("the test input has %d bytes and does not fit the input limit", len(padded))
	}
	got, err := typ.Normalize(padded)
	if err != nil || got != strings.Repeat("a", identifier.MaxValueLength) {
		t.Fatalf("a value that fits after trimming was rejected: %d bytes, %v", len(got), err)
	}
	if _, err = typ.Normalize(padded + "a"); err == nil {
		t.Fatal("a value that is one byte too long after trimming was accepted")
	}
}

func TestNormalizeStepError(t *testing.T) {
	failing := errors.New("step failed")
	typ := identifier.Custom("broken", identifier.Normalize(func(string) (string, error) { return "", failing }))
	if _, err := typ.Normalize("value"); !errors.Is(err, failing) {
		t.Fatalf("got %v, want %v", err, failing)
	}
}

func TestNormalizeRejectsNonIdempotentSteps(t *testing.T) {
	typ := identifier.Custom("drifting", identifier.Normalize(func(s string) (string, error) { return s + "x", nil }))
	if got, err := typ.Normalize("a"); err == nil {
		t.Fatalf("a value that changes on every normalization must be rejected, got %q", got)
	}
}

func TestZeroTypeIsRejected(t *testing.T) {
	var typ identifier.Type
	if typ.Err() == nil {
		t.Fatal("zero Type must report a configuration error")
	}
	if _, err := typ.Normalize("value"); err == nil {
		t.Fatal("zero Type must not normalize anything")
	}
	if typ.Name() != "" || typ.IsLogin() || typ.IsDelivery() || typ.IsRequired() {
		t.Fatal("zero Type must report no name and no flags")
	}
}

func TestInvalidConfigurationIsReportedByErr(t *testing.T) {
	cases := []struct {
		name string
		typ  identifier.Type
		want string
	}{
		{"pattern that does not compile", identifier.Custom("a", identifier.Pattern("[")), `invalid pattern "["`},
		{"negative minimum", identifier.Custom("a", identifier.Length(-1, 5)), "invalid length range -1..5"},
		{"maximum below minimum", identifier.Custom("a", identifier.Length(5, 4)), "invalid length range 5..4"},
		{"zero maximum", identifier.Custom("a", identifier.Length(0, 0)), "invalid length range 0..0"},
		{"nil validator", identifier.Custom("a", identifier.Validate(nil)), "Validate is nil"},
		{"nil normalizer", identifier.Custom("a", identifier.Normalize(nil)), "Normalize is nil"},
		{"empty name", identifier.Custom(""), `invalid type name ""`},
		{"upper case name", identifier.Custom("Upper"), `invalid type name "Upper"`},
		{"name starting with a digit", identifier.Custom("1abc"), `invalid type name "1abc"`},
		{"name with a space", identifier.Custom("with space"), `invalid type name "with space"`},
		{"name with a dash", identifier.Custom("with-dash"), `invalid type name "with-dash"`},
		{"name of 33 characters", identifier.Custom(strings.Repeat("a", 33)), "invalid type name"},
		{"bad option on the e-mail type", identifier.Email(identifier.Pattern("[")), "invalid pattern"},
		{"bad option on the nickname type", identifier.Username(identifier.Length(9, 3)), "invalid length range 9..3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.typ.Err()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Err() = %v, want an error containing %q", err, tc.want)
			}
			value, normalizeErr := tc.typ.Normalize("abc")
			if !errors.Is(normalizeErr, err) || value != "" {
				t.Fatalf("Normalize must fail with the configuration error, got %q, %v", value, normalizeErr)
			}
		})
	}
}

func TestFirstConfigurationErrorWins(t *testing.T) {
	first := errors.New("first problem")
	second := errors.New("second problem")
	typ := identifier.Custom("a", identifier.Invalid(first), identifier.Invalid(second), identifier.Pattern("["))
	if err := typ.Err(); !errors.Is(err, first) || errors.Is(err, second) {
		t.Fatalf("Err() = %v, want only the first problem", err)
	}
	typ = identifier.Custom("a", identifier.Pattern("["), identifier.Length(5, 4))
	if err := typ.Err(); err == nil || !strings.Contains(err.Error(), "invalid pattern") {
		t.Fatalf("Err() = %v, want the pattern problem", err)
	}
	typ = identifier.Custom("Bad", identifier.Pattern("["))
	if err := typ.Err(); err == nil || !strings.Contains(err.Error(), "invalid type name") {
		t.Fatalf("Err() = %v, want the name problem to come first", err)
	}
}

func TestInvalidOption(t *testing.T) {
	failing := errors.New("bad configuration")
	typ := identifier.Custom("a", identifier.Invalid(failing))
	if err := typ.Err(); !errors.Is(err, failing) {
		t.Fatalf("Err() = %v, want %v", err, failing)
	}
	if _, err := typ.Normalize("abc"); !errors.Is(err, failing) {
		t.Fatalf("Normalize = %v, want %v", err, failing)
	}
	if err := identifier.Custom("a", identifier.Invalid(nil)).Err(); err != nil {
		t.Fatalf("Invalid(nil) must change nothing, got %v", err)
	}
}

func TestNilOptionIsIgnored(t *testing.T) {
	typ := identifier.Custom("a", nil, identifier.LoginAllowed(), nil)
	if err := typ.Err(); err != nil || !typ.IsLogin() {
		t.Fatalf("a nil option must be skipped: err=%v login=%v", err, typ.IsLogin())
	}
}

func TestValidTypesReportNoError(t *testing.T) {
	for _, typ := range []identifier.Type{
		identifier.Email(),
		identifier.Username(),
		identifier.Custom("badge"),
		identifier.Custom("a_1", identifier.Pattern(`\d+`), identifier.Length(0, 10), identifier.Required()),
	} {
		if err := typ.Err(); err != nil {
			t.Errorf("%s: unexpected error %v", typ.Name(), err)
		}
	}
}

func TestResolveSkipsMisconfiguredTypes(t *testing.T) {
	types := []identifier.Type{
		identifier.Custom("broken", identifier.LoginAllowed(), identifier.Pattern("[")),
		identifier.Username(),
	}
	typ, value, err := identifier.Resolve(types, "Alice")
	if err != nil || typ.Name() != "username" || value != "alice" {
		t.Fatalf("got %q %q %v", typ.Name(), value, err)
	}
}

func TestBuiltInTypeFlags(t *testing.T) {
	email := identifier.Email()
	if email.Name() != "email" || !email.IsLogin() || !email.IsDelivery() || email.IsRequired() {
		t.Fatalf("unexpected e-mail flags: %q login=%v delivery=%v required=%v", email.Name(), email.IsLogin(), email.IsDelivery(), email.IsRequired())
	}
	username := identifier.Username(identifier.Required())
	if username.Name() != "username" || !username.IsLogin() || username.IsDelivery() || !username.IsRequired() {
		t.Fatalf("unexpected nickname flags: %q login=%v delivery=%v required=%v", username.Name(), username.IsLogin(), username.IsDelivery(), username.IsRequired())
	}
}

func TestEmailOptionsAddConstraints(t *testing.T) {
	typ := identifier.Email(identifier.Pattern(`.+@example\.com`), identifier.Required())
	runNormalizeCases(t, typ, []normalizeCase{
		{name: "allowed domain", raw: "Bob@Example.com", want: "bob@example.com"},
		{name: "other domain", raw: "bob@example.org", fail: true},
	})
}

func TestResolve(t *testing.T) {
	types := []identifier.Type{
		identifier.Email(),
		identifier.Custom("badge", identifier.Pattern(`[a-z]{3}\d{3}`)),
		identifier.Username(),
	}
	tests := []struct {
		name     string
		login    string
		wantType string
		want     string
		fail     bool
	}{
		{name: "email", login: " Bob@Example.com ", wantType: "email", want: "bob@example.com"},
		{name: "username", login: "Bobby", wantType: "username", want: "bobby"},
		{name: "type without login flag is skipped", login: "abc123", wantType: "username", want: "abc123"},
		{name: "nothing matches", login: "+79991234567", fail: true},
		{name: "empty", login: "", fail: true},
		{name: "digits only", login: "123456", fail: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			typ, value, err := identifier.Resolve(types, tc.login)
			if tc.fail {
				if err == nil {
					t.Fatalf("Resolve(%q) = %q %q, want an error", tc.login, typ.Name(), value)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q) failed: %v", tc.login, err)
			}
			if typ.Name() != tc.wantType || value != tc.want {
				t.Fatalf("Resolve(%q) = %q %q, want %q %q", tc.login, typ.Name(), value, tc.wantType, tc.want)
			}
		})
	}
}

func TestResolveUsesDeclarationOrder(t *testing.T) {
	first := identifier.Custom("first", identifier.LoginAllowed(), identifier.Pattern(`[a-z]+`))
	second := identifier.Custom("second", identifier.LoginAllowed(), identifier.Pattern(`[a-z]+`))
	typ, _, err := identifier.Resolve([]identifier.Type{first, second}, "abc")
	if err != nil || typ.Name() != "first" {
		t.Fatalf("got %q, %v; want the first declared type", typ.Name(), err)
	}
	typ, _, err = identifier.Resolve([]identifier.Type{second, first}, "abc")
	if err != nil || typ.Name() != "second" {
		t.Fatalf("got %q, %v; want the first declared type", typ.Name(), err)
	}
}

func TestResolveWithoutLoginTypes(t *testing.T) {
	if _, _, err := identifier.Resolve(nil, "alice"); err == nil {
		t.Fatal("Resolve with no types must fail")
	}
	if _, _, err := identifier.Resolve([]identifier.Type{identifier.Custom("badge")}, "alice"); err == nil {
		t.Fatal("Resolve with no login types must fail")
	}
}

func TestBuiltInFormatsDoNotOverlap(t *testing.T) {
	email := identifier.Email()
	username := identifier.Username()
	samples := []string{"alice", "alice@example.com", "a.b-c_d", "+79991234567", "79991234567", "a@b.c", "x@y"}
	for _, sample := range samples {
		_, emailErr := email.Normalize(sample)
		_, usernameErr := username.Normalize(sample)
		if emailErr == nil && usernameErr == nil {
			t.Fatalf("%q is accepted by both the e-mail and the nickname type", sample)
		}
	}
}
