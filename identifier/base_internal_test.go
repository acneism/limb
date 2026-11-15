package identifier

import (
	"testing"
)

func fuzzBase(f *testing.F, base step, seeds []string) {
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := base(raw)
		if err != nil {
			return
		}
		again, err := base(got)
		if err != nil || again != got {
			t.Fatalf("base normalization is not idempotent: %q -> %q -> %q (%v)", raw, got, again, err)
		}
	})
}

func FuzzNormalizeEmailBase(f *testing.F) {
	fuzzBase(f, normalizeEmail, []string{
		"a@b.co", "Alice@Example.COM", "user@пример.рф", "user@xn--e1afmkfd.xn--p1ai", "ß@straße.de",
		"user@ｅｘａｍｐｌｅ.ｃｏｍ", "a@b.c\u200do", "a@xn--a.co", "a@b.co。", "a@١.co", "a@ǆ.co", "a@ᾈ.co",
	})
}

func FuzzNormalizeUsernameBase(f *testing.F) {
	fuzzBase(f, normalizeUsername, []string{
		"alice", "Alice_01", "ＢＯＢ", "ﬁsh", "ß", "İstanbul", "ǅ", "ᾈ", "\u0345", "Σίσυφος", "ﷺ", "ŉ", "ǰ", "\u00a0a\u00a0", "a\u3000",
	})
}
