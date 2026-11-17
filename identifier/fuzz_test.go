package identifier_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/acneism/limb/identifier"
)

func fuzzType(f *testing.F, typ identifier.Type, seeds []string) {
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := typ.Normalize(raw)
		if err != nil {
			return
		}
		if got == "" || !utf8.ValidString(got) || strings.IndexFunc(got, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0 {
			t.Fatalf("Normalize(%q) = %q is not a clean non-empty string", raw, got)
		}
		again, err := typ.Normalize(got)
		if err != nil || again != got {
			t.Fatalf("Normalize is not idempotent: %q -> %q -> %q (%v)", raw, got, again, err)
		}
	})
}

func FuzzEmail(f *testing.F) {
	fuzzType(f, identifier.Email(), []string{
		"", "a@b.co", "Alice@Example.COM", "user@пример.рф", "user@xn--e1afmkfd.xn--p1ai",
		"Name <a@b.co>", "a@b", "a@@b.co", "a@b.co.", "user@ｅｘａｍｐｌｅ.ｃｏｍ", "ß@straße.de",
		"a@xn--", "a@xn--a.co", "a@b.c\u200do", "a@١.co", "\x00@a.co", "a@b.co。",
	})
}

func FuzzUsername(f *testing.F) {
	fuzzType(f, identifier.Username(), []string{
		"", "alice", "Alice_01", "ＢＯＢ", "ﬁsh", "123456", "+alice", "a@b", "ß", "İstanbul", "ǅ", "ᾈ", "\u0345",
	})
}

func FuzzUsernameUnicode(f *testing.F) {
	fuzzType(f, identifier.Username(identifier.Pattern(`.+`), identifier.Length(1, 64)), []string{
		"", "alice", "ＢＯＢ", "ﬁsh", "ß", "İstanbul", "ǅ", "ᾈ", "\u0345", "Σίσυφος", "ﷺ", "ŉ", "ǰ",
	})
}

func FuzzCustom(f *testing.F) {
	fuzzType(f, identifier.Custom("badge", identifier.Pattern(`[a-z0-9]+`), identifier.Length(2, 12)), []string{
		"", "ab", "a1b2c3", " ab ", "AB", "a b", "\u00a0ab\u00a0",
	})
}

func FuzzResolveDelivery(f *testing.F) {
	types := []identifier.Type{
		identifier.Email(identifier.Required()),
		identifier.Username(),
		identifier.Custom("sms", identifier.Pattern(`\+[0-9]{10,14}`), identifier.Delivery()),
	}
	for _, seed := range []string{"", "a@b.co", "+79991234567", "alice_01", " Alice@Example.com ", "+7 999", "\x00", "user@пример.рф"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		typ, value, err := identifier.ResolveDelivery(types, raw)
		if err != nil {
			return
		}
		if !typ.IsDelivery() || value == "" || !utf8.ValidString(value) {
			t.Fatalf("ResolveDelivery(%q) = %s, %q", raw, typ.Name(), value)
		}
		again, err := typ.Normalize(value)
		if err != nil || again != value {
			t.Fatalf("the value of ResolveDelivery(%q) is not normalized: %q -> %q (%v)", raw, value, again, err)
		}
	})
}
