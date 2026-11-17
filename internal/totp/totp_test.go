package totp

import (
	"bytes"
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func rfcSeed() []byte {
	return bytes.Repeat([]byte("1234567890"), 2)
}

func TestTheCounterBasedPasswordsFollowRFC4226(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, code := range want {
		if got := hotp(rfcSeed(), uint64(counter), 6); got != code {
			t.Errorf("the password for the counter %d is %s, RFC 4226 gives %s", counter, got, code)
		}
	}
}

func TestTheTimeBasedPasswordsFollowRFC6238(t *testing.T) {
	cases := []struct {
		unix int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		step := Step(time.Unix(c.unix, 0))
		if got := hotp(rfcSeed(), uint64(max(0, step)), 8); got != c.code {
			t.Errorf("at %d the password is %s, RFC 6238 gives %s", c.unix, got, c.code)
		}
		if got := Code(rfcSeed(), step); got != c.code[2:] {
			t.Errorf("at %d the six digit password is %s, want the last six digits of %s", c.unix, got, c.code)
		}
	}
}

func TestAStepIsThirtySecondsLong(t *testing.T) {
	for unix, want := range map[int64]int64{0: 0, 29: 0, 30: 1, 59: 1, 60: 2, 1799: 59, 1800: 60, -1: 0, -100000: 0} {
		if got := Step(time.Unix(unix, 0)); got != want {
			t.Errorf("the step of %d is %d, want %d", unix, got, want)
		}
	}
	if Step(time.Unix(59, 999999999)) != 1 || Step(time.Unix(60, 0)) != 2 {
		t.Fatal("a step ends at the second, not before it")
	}
}

func TestACodeHasSixDigitsWithLeadingZeros(t *testing.T) {
	seed := rfcSeed()
	zeros := 0
	for step := range int64(3000) {
		code := Code(seed, step)
		if len(code) != Digits || strings.Trim(code, "0123456789") != "" {
			t.Fatalf("the code of the step %d is %q", step, code)
		}
		if code[0] == '0' {
			zeros++
		}
	}
	if zeros == 0 {
		t.Fatal("no code of 3000 starts with a zero: the zeros must be kept")
	}
}

func TestVerifyAcceptsTheStepsOfTheWindowAndNoOthers(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, SecretLength)
	now := time.Unix(1_700_000_010, 0)
	current := Step(now)
	for delta := int64(-4); delta <= 4; delta++ {
		step, ok := Verify(seed, Code(seed, current+delta), now)
		inWindow := delta >= -Window && delta <= Window
		if ok != inWindow || (ok && step != current+delta) {
			t.Errorf("the password of the step %+d: Verify = %d, %v; want %v", delta, step, ok, inWindow)
		}
	}
}

func TestVerifyTakesTheStepOfTheMomentNotOfTheCodeThatIsGivenBack(t *testing.T) {
	seed := bytes.Repeat([]byte{9}, SecretLength)
	boundary := time.Unix(30*1000, 0)
	for _, now := range []time.Time{boundary.Add(-time.Nanosecond), boundary, boundary.Add(29*time.Second + 999*time.Millisecond), boundary.Add(30 * time.Second)} {
		current := Step(now)
		if step, ok := Verify(seed, Code(seed, current), now); !ok || step != current {
			t.Errorf("at %v the password of the current step %d gives %d, %v", now, current, step, ok)
		}
	}
}

func TestVerifyAcceptsAPasswordAsItIsTyped(t *testing.T) {
	seed := bytes.Repeat([]byte{5}, SecretLength)
	now := time.Unix(1_700_000_000, 0)
	code := Code(seed, Step(now))
	for _, typed := range []string{code, " " + code + " ", code[:3] + " " + code[3:], code[:3] + "-" + code[3:], "\t" + code + "\n"} {
		if _, ok := Verify(seed, typed, now); !ok {
			t.Errorf("%q was refused", typed)
		}
	}
	other := code[:5] + string(rune('0'+(code[5]-'0'+1)%10))
	for name, typed := range map[string]string{
		"a wrong password":         other,
		"nothing":                  "",
		"five digits":              code[:5],
		"seven digits":             code + "0",
		"letters":                  "abcdef",
		"the password and a tail":  code + " x",
		"two gaps":                 code[:2] + " " + code[2:4] + " " + code[4:],
		"digits of another script": "١٢٣٤٥٦",
		"a zero width space":       code[:3] + "\u200b" + code[3:],
	} {
		if step, ok := Verify(seed, typed, now); ok {
			t.Errorf("%s was accepted at the step %d", name, step)
		}
	}
}

func TestVerifyRefusesWithoutASeed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, seed := range [][]byte{nil, {}} {
		for step := Step(now) - 1; step <= Step(now)+1; step++ {
			if _, ok := Verify(seed, Code(seed, step), now); ok {
				t.Fatal("a password was accepted without a seed")
			}
		}
	}
}

func TestVerifyDoesNotLookBeforeTheStartOfTime(t *testing.T) {
	seed := bytes.Repeat([]byte{3}, SecretLength)
	now := time.Unix(10, 0)
	if step, ok := Verify(seed, Code(seed, 0), now); !ok || step != 0 {
		t.Fatalf("the password of the step 0 at the step 0 = %d, %v", step, ok)
	}
	if step, ok := Verify(seed, Code(seed, 1), now); !ok || step != 1 {
		t.Fatalf("the password of the next step at the step 0 = %d, %v", step, ok)
	}
	if _, ok := Verify(seed, Code(seed, -1), now); !ok {
		t.Fatal("a step before the start is the step 0, whose password works")
	}
}

func TestTheLaterStepWinsWhenAPasswordFitsTwo(t *testing.T) {
	seed := bytes.Repeat([]byte{12}, SecretLength)
	const first = 3633
	if Code(seed, first) != Code(seed, first+1) || Code(seed, first) != "552262" {
		t.Fatalf("the seed no longer has the same password in the steps %d and %d: %s, %s", first, first+1, Code(seed, first), Code(seed, first+1))
	}
	cases := []struct {
		now  int64
		want int64
		ok   bool
	}{
		{first - 1, first, true},
		{first, first + 1, true},
		{first + 1, first + 1, true},
		{first + 2, first + 1, true},
		{first + 3, 0, false},
		{first - 2, 0, false},
	}
	for _, c := range cases {
		got, ok := Verify(seed, "552262", time.Unix(c.now*StepSeconds, 0))
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("at the step %d the password of the steps %d and %d gives %d, %v; want %d, %v", c.now, first, first+1, got, ok, c.want, c.ok)
		}
	}
}

func TestASeedIsTwentyRandomBytes(t *testing.T) {
	first, err := NewSecret()
	if err != nil || len(first) != SecretLength {
		t.Fatalf("NewSecret = %d bytes, %v", len(first), err)
	}
	second, err := NewSecret()
	if err != nil || bytes.Equal(first, second) {
		t.Fatalf("two seeds are the same: %x, %v", first, err)
	}
	source := bytes.Repeat([]byte{0xAB}, 64)
	got, err := newSecret(bytes.NewReader(source))
	if err != nil || !bytes.Equal(got, source[:SecretLength]) {
		t.Fatalf("the seed must be the first bytes of the source: %x, %v", got, err)
	}
}

func TestASeedThatCannotBeMadeIsReported(t *testing.T) {
	broken := errors.New("no randomness")
	if seed, err := newSecret(iotest.ErrReader(broken)); !errors.Is(err, broken) || seed != nil {
		t.Fatalf("newSecret = %v, %v; want the failure of the source", seed, err)
	}
	if seed, err := newSecret(bytes.NewReader(make([]byte, SecretLength-1))); err == nil || seed != nil {
		t.Fatalf("newSecret from a short source = %v, %v; want an error", seed, err)
	}
}

func TestASeedIsWrittenInBase32WithoutPadding(t *testing.T) {
	seed := rfcSeed()
	text := EncodeSecret(seed)
	if text != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" {
		t.Fatalf("the seed of RFC 4226 is written as %s", text)
	}
	if strings.ContainsAny(text, "=0189 ") || text != strings.ToUpper(text) {
		t.Fatalf("%q is not upper case base32 without padding", text)
	}
	if back, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(text); err != nil || !bytes.Equal(back, seed) {
		t.Fatalf("the text does not decode to the seed: %v", err)
	}
}

func TestTheAddressOfAnAccountCarriesWhatAnAuthenticatorNeeds(t *testing.T) {
	seed := rfcSeed()
	address := URI("Acme", "root", seed)
	parsed, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.Path != "/Acme:root" {
		t.Fatalf("the address is %s", address)
	}
	query := parsed.Query()
	want := map[string]string{"secret": EncodeSecret(seed), "issuer": "Acme", "algorithm": "SHA1", "digits": "6", "period": "30"}
	for key, value := range want {
		if query.Get(key) != value {
			t.Errorf("%s is %q, want %q", key, query.Get(key), value)
		}
	}
	if len(query) != len(want) {
		t.Errorf("the address has parameters that are not needed: %v", query)
	}
}

func TestTheAddressOfAnAccountSurvivesAwkwardNames(t *testing.T) {
	seed := rfcSeed()
	for _, c := range []struct{ issuer, account, wantIssuer, wantAccount string }{
		{"Ac me & Co / 100%", "ro ot", "Ac me & Co / 100%", "ro ot"},
		{"Акме \U0001F600", "я", "Акме \U0001F600", "я"},
		{"Acme: Inc", "a:b", "Acme  Inc", "a b"},
		{"", "root", "", "root"},
		{"a?b#c", "x?y#z", "a?b#c", "x?y#z"},
	} {
		parsed, err := url.Parse(URI(c.issuer, c.account, seed))
		if err != nil {
			t.Errorf("%q, %q: %v", c.issuer, c.account, err)
			continue
		}
		label := strings.TrimPrefix(parsed.Path, "/")
		issuer, account, found := strings.Cut(label, ":")
		if !found || issuer != c.wantIssuer || account != c.wantAccount || parsed.Query().Get("issuer") != c.wantIssuer {
			t.Errorf("%q, %q: the label is %q and the issuer %q, want %q and %q", c.issuer, c.account, label, parsed.Query().Get("issuer"), c.wantIssuer+":"+c.wantAccount, c.wantIssuer)
		}
		if parsed.Query().Get("secret") != EncodeSecret(seed) {
			t.Errorf("%q, %q: the seed was damaged", c.issuer, c.account)
		}
	}
}

func FuzzVerify(f *testing.F) {
	seed := bytes.Repeat([]byte{4}, SecretLength)
	now := time.Unix(1_700_000_000, 0)
	for _, input := range []string{"", "123456", "123 456", "123-456", " 123456 ", "12345", "1234567", "abcdef", Code(seed, Step(now)), "١٢٣٤٥٦", "123\x00456"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		step, ok := Verify(seed, input, now)
		if !ok {
			return
		}
		typed := strings.NewReplacer(" ", "", "-", "", "\t", "", "\n", "", "\r", "", "\v", "", "\f", "").Replace(input)
		if len(typed) != Digits || typed != Code(seed, step) {
			t.Fatalf("%q was accepted for the step %d, whose password is %s", input, step, Code(seed, step))
		}
		if step < Step(now)-Window || step > Step(now)+Window {
			t.Fatalf("the step %d is out of the window around %d", step, Step(now))
		}
	})
}
