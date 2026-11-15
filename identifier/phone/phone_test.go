package phone_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/acneism/limb/identifier"
	"github.com/acneism/limb/identifier/phone"
)

type normalizeCase struct {
	name   string
	region string
	raw    string
	want   string
	fail   bool
}

func runCases(t *testing.T, cases []normalizeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := phone.Number(tc.region).Normalize(tc.raw)
			if tc.fail {
				if err == nil {
					t.Fatalf("Normalize(%q) = %q, want an error", tc.raw, got)
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

func TestNumberNormalize(t *testing.T) {
	runCases(t, []normalizeCase{
		{name: "national with trunk prefix", region: "RU", raw: "8 (926) 123-45-67", want: "+79261234567"},
		{name: "national without trunk prefix", region: "RU", raw: "926 123 45 67", want: "+79261234567"},
		{name: "international", region: "RU", raw: "+7 926 123-45-67", want: "+79261234567"},
		{name: "international ignores the region", region: "US", raw: "+7 926 123-45-67", want: "+79261234567"},
		{name: "dots as separators", region: "RU", raw: "8.926.123.45.67", want: "+79261234567"},
		{name: "fullwidth characters", region: "RU", raw: "＋７\u3000９２６\u3000１２３\u3000４５\u3000６７", want: "+79261234567"},
		{name: "surrounding space", region: "RU", raw: "  +79261234567\n", want: "+79261234567"},
		{name: "united states", region: "US", raw: "(650) 253-0000", want: "+16502530000"},
		{name: "united kingdom", region: "GB", raw: "07911 123456", want: "+447911123456"},
		{name: "no region needs plus", region: "", raw: "+44 7911 123456", want: "+447911123456"},
		{name: "no region without plus", region: "", raw: "07911 123456", fail: true},
		{name: "empty", region: "RU", raw: "", fail: true},
		{name: "plus only", region: "RU", raw: "+", fail: true},
		{name: "too short", region: "RU", raw: "12345", fail: true},
		{name: "invalid number", region: "RU", raw: "+7 000 000 00 00", fail: true},
		{name: "vanity number", region: "US", raw: "1-800-FLOWERS", fail: true},
		{name: "text around the number", region: "RU", raw: "call 89261234567", fail: true},
		{name: "trailing text", region: "RU", raw: "89261234567x", fail: true},
		{name: "extension", region: "RU", raw: "89261234567 ext 12", fail: true},
		{name: "double plus", region: "RU", raw: "++79261234567", fail: true},
		{name: "plus inside", region: "RU", raw: "7926+1234567", fail: true},
		{name: "letters only", region: "RU", raw: "abcdefghij", fail: true},
		{name: "control character", region: "RU", raw: "89261234567\x00", fail: true},
		{name: "invalid utf-8", region: "RU", raw: "89261234567\xff", fail: true},
		{name: "too long", region: "RU", raw: strings.Repeat("9", 40), fail: true},
	})
}

func TestNumberFlagsAndOptions(t *testing.T) {
	typ := phone.Number("RU")
	if typ.Name() != "phone" || !typ.IsLogin() || !typ.IsDelivery() || typ.IsRequired() {
		t.Fatalf("unexpected flags: %q login=%v delivery=%v required=%v", typ.Name(), typ.IsLogin(), typ.IsDelivery(), typ.IsRequired())
	}
	required := phone.Number("RU", identifier.Required())
	if !required.IsRequired() {
		t.Fatal("options must be passed through to the type")
	}
}

func TestNumberValidatorSeesE164Value(t *testing.T) {
	var seen []string
	typ := phone.Number("RU", identifier.Validate(func(s string) error {
		seen = append(seen, s)
		if strings.HasPrefix(s, "+7926") {
			return errors.New("range is not accepted")
		}
		return nil
	}))
	if got, err := typ.Normalize("8 926 123 45 67"); err == nil {
		t.Fatalf("got %q, want the validator to reject the number", got)
	}
	if len(seen) == 0 || seen[0] != "+79261234567" {
		t.Fatalf("validator must see the normalized value, saw %q", seen)
	}
	if got, err := typ.Normalize("8 916 123 45 67"); err != nil || got != "+79161234567" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNumberReportsUnsupportedRegion(t *testing.T) {
	for _, region := range []string{"XX", "RUS", "1", " ", "R", "r u"} {
		typ := phone.Number(region)
		if err := typ.Err(); err == nil || !strings.Contains(err.Error(), "unsupported region") {
			t.Fatalf("Number(%q).Err() = %v, want an unsupported region error", region, err)
		}
		if got, err := typ.Normalize("+79261234567"); err == nil {
			t.Fatalf("a misconfigured type must reject everything, got %q", got)
		}
	}
	for _, region := range []string{"", "RU", "US", "GB"} {
		if err := phone.Number(region).Err(); err != nil {
			t.Fatalf("Number(%q).Err() = %v", region, err)
		}
	}
}

func TestNumberAcceptsTheRegionInAnyCase(t *testing.T) {
	for _, region := range []string{"RU", "ru", "Ru", "rU"} {
		typ := phone.Number(region)
		if err := typ.Err(); err != nil {
			t.Fatalf("Number(%q).Err() = %v", region, err)
		}
		if got, err := typ.Normalize("8 926 123 45 67"); err != nil || got != "+79261234567" {
			t.Fatalf("Number(%q) normalized to %q, %v", region, got, err)
		}
	}
	if err := phone.Number("zz").Err(); err == nil || !strings.Contains(err.Error(), `"zz"`) {
		t.Fatalf("the error must show the region as given, got %v", err)
	}
}

func TestNumberKeepsErrorsOfItsOptions(t *testing.T) {
	if err := phone.Number("RU", identifier.Pattern("[")).Err(); err == nil || !strings.Contains(err.Error(), "invalid pattern") {
		t.Fatalf("Err() = %v, want the option problem", err)
	}
	if err := phone.Number("XX", identifier.Pattern("[")).Err(); err == nil || !strings.Contains(err.Error(), "unsupported region") {
		t.Fatalf("Err() = %v, want the region problem first", err)
	}
}

func TestNumberIsResolvedBeforeUsernames(t *testing.T) {
	types := []identifier.Type{identifier.Email(), phone.Number("RU"), identifier.Username()}
	typ, value, err := identifier.Resolve(types, "8 926 123 45 67")
	if err != nil || typ.Name() != "phone" || value != "+79261234567" {
		t.Fatalf("got %q %q %v", typ.Name(), value, err)
	}
	typ, value, err = identifier.Resolve(types, "a89261234567")
	if err != nil || typ.Name() != "username" || value != "a89261234567" {
		t.Fatalf("a nickname with digits must not be taken for a phone number, got %q %q %v", typ.Name(), value, err)
	}
	if _, _, err = identifier.Resolve(types, "+79261234567x"); err == nil {
		t.Fatal("text after a number must not resolve to any type")
	}
}

func fuzzNumber(f *testing.F, region string) {
	for _, seed := range []string{"", "+", "8 926 123 45 67", "+79261234567", "(650) 253-0000", "07911 123456", "1-800-FLOWERS", "+７９２６１２３４５６７", "\x00", "++1", "9" + strings.Repeat("9", 30)} {
		f.Add(seed)
	}
	typ := phone.Number(region)
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := typ.Normalize(raw)
		if err != nil {
			return
		}
		if !utf8.ValidString(got) || !strings.HasPrefix(got, "+") {
			t.Fatalf("Normalize(%q) = %q, not an E.164 value", raw, got)
		}
		again, err := typ.Normalize(got)
		if err != nil || again != got {
			t.Fatalf("Normalize is not idempotent: %q -> %q -> %q (%v)", raw, got, again, err)
		}
	})
}

func FuzzNumberRU(f *testing.F) {
	fuzzNumber(f, "RU")
}

func FuzzNumberNoRegion(f *testing.F) {
	fuzzNumber(f, "")
}
