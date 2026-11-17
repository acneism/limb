package secret

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
)

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

func drawn(values ...uint32) io.Reader {
	var raw []byte
	for _, v := range values {
		raw = binary.BigEndian.AppendUint32(raw, v)
	}
	return bytes.NewReader(raw)
}

func TestNewCodeIsSixDigits(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	seen := map[string]bool{}
	for range 2000 {
		code, err := k.NewCode()
		if err != nil {
			t.Fatalf("NewCode failed: %v", err)
		}
		if !sixDigits.MatchString(code) {
			t.Fatalf("NewCode = %q, want six digits", code)
		}
		seen[code] = true
	}
	if len(seen) < 1900 {
		t.Fatalf("2000 codes had only %d different values", len(seen))
	}
}

func TestNewCodeTakesTheRemainderOfTheValueOfTheSource(t *testing.T) {
	cases := map[uint32]string{
		0:                "000000",
		1:                "000001",
		999999:           "999999",
		1_000_000:        "000000",
		1_234_567:        "234567",
		123_456_789:      "456789",
		codeLimit - 1:    "999999",
		codeLimit - 1000: "999000",
	}
	for value, want := range cases {
		k := newKeys(t, randomMaster(t))
		k.random = drawn(value)
		if got, err := k.NewCode(); err != nil || got != want {
			t.Errorf("NewCode with the value %d = %q, %v; want %q", value, got, err, want)
		}
	}
}

func TestNewCodeThrowsAwayTheIncompleteLastBlock(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	source := drawn(codeLimit, 4_294_967_295, 42)
	k.random = source
	got, err := k.NewCode()
	if err != nil || got != "000042" {
		t.Fatalf("NewCode = %q, %v; want %q after two values were thrown away", got, err, "000042")
	}
	if rest, _ := io.ReadAll(source); len(rest) != 0 {
		t.Fatalf("%d bytes are left, want the three values to have been read", len(rest))
	}
}

func TestEveryCodeHasTheSameNumberOfValuesOfTheSource(t *testing.T) {
	if codeLimit%codeSpace != 0 {
		t.Fatalf("the range %d is not a multiple of the number of codes %d, so the codes would be biased", uint64(codeLimit), codeSpace)
	}
	if uint64(codeLimit)+codeSpace <= 1<<32 {
		t.Fatalf("the range %d wastes a whole block of values", uint64(codeLimit))
	}
}

func TestNewCodeGivesUpOnASourceThatNeverHelps(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	source := bytes.NewReader(bytes.Repeat([]byte{0xff}, 4*(codeDraws+10)))
	k.random = source
	if code, err := k.NewCode(); !errors.Is(err, ErrNoCode) || code != "" {
		t.Fatalf("NewCode = %q, %v; want ErrNoCode", code, err)
	}
	if source.Len() != 40 {
		t.Fatalf("NewCode read %d values, want %d", (4*(codeDraws+10)-source.Len())/4, codeDraws)
	}
}

func TestNewCodeReportsRandomFailure(t *testing.T) {
	boom := errors.New("boom")
	for name, source := range map[string]io.Reader{
		"an error":    iotest.ErrReader(boom),
		"a short one": bytes.NewReader([]byte{1, 2}),
		"nothing":     bytes.NewReader(nil),
	} {
		k := newKeys(t, randomMaster(t))
		k.random = source
		if code, err := k.NewCode(); err == nil || code != "" {
			t.Errorf("NewCode with %s = %q, %v; want an error", name, code, err)
		}
	}
	k := newKeys(t, randomMaster(t))
	k.random = iotest.ErrReader(boom)
	if _, err := k.NewCode(); !errors.Is(err, boom) {
		t.Fatalf("NewCode = %v, want the error of the source to be wrapped", err)
	}
}

var binding = CodeBinding{
	TenantID:     "default",
	ID:           "0190-id",
	UserID:       "0190-user",
	Purpose:      "reset",
	ChannelType:  "email",
	ChannelValue: "alice@example.com",
}

func TestCodeHashIsTheHMACOfTheFramedBinding(t *testing.T) {
	master := randomMaster(t)
	k := newKeys(t, master)
	small := CodeBinding{TenantID: "t", ID: "i", UserID: "u", Purpose: "reset", ChannelType: "email", ChannelValue: "a@b"}
	framed := []byte{1, 't', 1, 'i', 1, 'u', 5, 'r', 'e', 's', 'e', 't', 5, 'e', 'm', 'a', 'i', 'l', 3, 'a', '@', 'b', 6, '1', '2', '3', '4', '5', '6'}
	want := referenceMAC(referenceHKDF(master, "limb/v1/codes"), framed)
	if got := k.CodeHash(small, "123456"); !bytes.Equal(got, want) {
		t.Fatalf("CodeHash = %x, want %x", got, want)
	}
	if len(want) != 32 {
		t.Fatalf("the hash has %d bytes, want 32", len(want))
	}
}

func TestCodeHashDependsOnEveryPart(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	other := newKeys(t, randomMaster(t))
	base := k.CodeHash(binding, "123456")
	if !bytes.Equal(base, k.CodeHash(binding, "123456")) {
		t.Fatal("CodeHash is not deterministic")
	}
	edits := map[string]func(*CodeBinding){
		"tenant":        func(b *CodeBinding) { b.TenantID = "second" },
		"ID":            func(b *CodeBinding) { b.ID += "x" },
		"user":          func(b *CodeBinding) { b.UserID += "x" },
		"purpose":       func(b *CodeBinding) { b.Purpose = "verify" },
		"channel type":  func(b *CodeBinding) { b.ChannelType = "phone" },
		"channel value": func(b *CodeBinding) { b.ChannelValue = "bob@example.com" },
	}
	for name, edit := range edits {
		changed := binding
		edit(&changed)
		if bytes.Equal(k.CodeHash(changed, "123456"), base) {
			t.Errorf("the hash does not depend on the %s", name)
		}
	}
	if bytes.Equal(k.CodeHash(binding, "123457"), base) {
		t.Error("the hash does not depend on the code")
	}
	if bytes.Equal(other.CodeHash(binding, "123456"), base) {
		t.Error("the hash does not depend on the master key")
	}
	shifted := binding
	shifted.ID, shifted.UserID = binding.ID+"0190", "-user"
	if bytes.Equal(k.CodeHash(shifted, "123456"), base) {
		t.Error("moving characters from one part to the next gives the same hash")
	}
}

func TestCodeHashDoesNotLeakTheCode(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	hash := k.CodeHash(binding, "123456")
	if bytes.Contains(hash, []byte("123456")) || strings.Contains(string(hash), "123456") {
		t.Fatal("the hash contains the code")
	}
}

func TestCodeMatches(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	other := newKeys(t, randomMaster(t))
	stored := k.CodeHash(binding, "123456")
	elsewhere := binding
	elsewhere.UserID = "another"
	cases := []struct {
		name    string
		keys    *Keys
		stored  []byte
		binding CodeBinding
		code    string
		want    bool
	}{
		{"the right code", k, stored, binding, "123456", true},
		{"a wrong code", k, stored, binding, "123457", false},
		{"no code", k, stored, binding, "", false},
		{"another binding", k, stored, elsewhere, "123456", false},
		{"another master key", other, stored, binding, "123456", false},
		{"no stored hash", k, nil, binding, "123456", false},
		{"a short hash", k, stored[:31], binding, "123456", false},
		{"a long hash", k, append(bytes.Clone(stored), 0), binding, "123456", false},
		{"a hash of another code", k, k.CodeHash(binding, "000000"), binding, "123456", false},
	}
	for _, c := range cases {
		if got := c.keys.CodeMatches(c.stored, c.binding, c.code); got != c.want {
			t.Errorf("%s: CodeMatches = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseCode(t *testing.T) {
	accepted := map[string]string{
		"123456":       "123456",
		"000000":       "000000",
		"  123456  ":   "123456",
		"\t123456\n":   "123456",
		"123 456":      "123456",
		"123-456":      "123456",
		" 123-456 ":    "123456",
		"\u00a0123456": "123456",
		"999999":       "999999",
		"012345":       "012345",
	}
	for input, want := range accepted {
		if got, ok := ParseCode(input); !ok || got != want {
			t.Errorf("ParseCode(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
	refused := []string{
		"", " ", "1", "12345", "1234567", "12345 6", "1234-56", "123  456", "123--456", "123_456", "123.456", "123\t456",
		"12345a", "a23456", "12 3456", "-23456", "123456-", "+12345", "\u0661\u0662\u0663\u0664\u0665\u0666", "\uff11\uff12\uff13\uff14\uff15\uff16", "123456\x00", "\x00123456",
		"123 45", "1 2 3 4 5 6", strings.Repeat("1", 1000), strings.Repeat(" ", 1000), "123456 7", "1.23456", "0x1234",
	}
	for _, input := range refused {
		if got, ok := ParseCode(input); ok || got != "" {
			t.Errorf("ParseCode(%q) = %q, %v; want a refusal", input, got, ok)
		}
	}
}

func FuzzParseCode(f *testing.F) {
	for _, seed := range []string{"123456", "123 456", "123-456", "", " 12345", "\u0661\u0662\u0663\u0664\u0665\u0666", "12345\x00", strings.Repeat("9", 100)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		code, ok := ParseCode(input)
		if !ok {
			if code != "" {
				t.Fatalf("ParseCode(%q) refused but returned %q", input, code)
			}
			return
		}
		if !sixDigits.MatchString(code) {
			t.Fatalf("ParseCode(%q) = %q, want six ASCII digits", input, code)
		}
		if again, ok := ParseCode(code); !ok || again != code {
			t.Fatalf("ParseCode is not idempotent: %q gave %q and then %q, %v", input, code, again, ok)
		}
		if len(strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, input)) != CodeDigits {
			t.Fatalf("ParseCode(%q) = %q took something other than the digits of the input", input, code)
		}
	})
}
