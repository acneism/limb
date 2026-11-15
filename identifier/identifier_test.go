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

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s did not panic", name)
		}
	}()
	fn()
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
	if _, err := typ.Normalize("value"); err == nil {
		t.Fatal("zero Type must not normalize anything")
	}
	if typ.Name() != "" || typ.IsLogin() || typ.IsDelivery() || typ.IsRequired() {
		t.Fatal("zero Type must report no name and no flags")
	}
}

func TestOptionsPanicOnInvalidArguments(t *testing.T) {
	mustPanic(t, "Pattern with an invalid expression", func() { identifier.Pattern("[") })
	mustPanic(t, "Length with a negative minimum", func() { identifier.Length(-1, 5) })
	mustPanic(t, "Length with maximum below minimum", func() { identifier.Length(5, 4) })
	mustPanic(t, "Length with a zero maximum", func() { identifier.Length(0, 0) })
	mustPanic(t, "Validate with nil", func() { identifier.Validate(nil) })
	mustPanic(t, "Normalize with nil", func() { identifier.Normalize(nil) })
	for _, name := range []string{"", "Upper", "1abc", "with space", "with-dash", strings.Repeat("a", 33)} {
		mustPanic(t, "Custom("+name+")", func() { identifier.Custom(name) })
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
