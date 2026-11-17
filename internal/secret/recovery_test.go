package secret

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

func TestARecoveryCodeIsTwentyFiveCharactersOfTheAlphabet(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	seen := map[string]bool{}
	for range 200 {
		code, err := k.NewRecoveryCode()
		if err != nil {
			t.Fatalf("NewRecoveryCode failed: %v", err)
		}
		if len(code) != RecoveryCodeLength || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
			t.Fatalf("the code %q is not %d characters of A to Z and 2 to 7", code, RecoveryCodeLength)
		}
		if seen[code] {
			t.Fatalf("the code %q was made twice", code)
		}
		seen[code] = true
	}
}

func TestEveryCharacterOfARecoveryCodeIsTheLowFiveBitsOfARandomByte(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	raw := []byte{5, 42, 79, 116, 153, 190, 227, 8, 45, 82, 119, 156, 193, 230, 11, 48, 85, 122, 159, 196, 233, 14, 51, 88, 125}
	k.random = bytes.NewReader(raw)
	code, err := k.NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range raw {
		if want := recoveryAlphabet[b&31]; code[i] != want {
			t.Fatalf("character %d of the code is %c, the byte %d makes %c", i, code[i], b, want)
		}
	}
	all := make([]byte, 0, 256)
	for b := range 256 {
		all = append(all, byte(b))
	}
	counts := map[byte]int{}
	for _, b := range all {
		counts[recoveryAlphabet[b&31]]++
	}
	for c, n := range counts {
		if n != 8 {
			t.Fatalf("the character %c is made by %d of the 256 bytes, want 8: no character may be more likely", c, n)
		}
	}
}

func TestARecoveryCodeThatCannotBeMadeIsReported(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	broken := errors.New("no randomness")
	k.random = iotest.ErrReader(broken)
	if code, err := k.NewRecoveryCode(); !errors.Is(err, broken) || code != "" {
		t.Fatalf("NewRecoveryCode = %q, %v; want the failure of the source", code, err)
	}
	k.random = bytes.NewReader(make([]byte, RecoveryCodeLength-1))
	if code, err := k.NewRecoveryCode(); err == nil || code != "" {
		t.Fatalf("NewRecoveryCode from a short source = %q, %v; want an error", code, err)
	}
}

func TestARecoveryCodeIsWrittenInGroupsOfFive(t *testing.T) {
	code := "ABCDEFGHIJKLMNOPQRSTUVWXY"
	if got := FormatRecoveryCode(code); got != "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY" {
		t.Fatalf("FormatRecoveryCode = %q", got)
	}
	if got := FormatRecoveryCode(""); got != "" {
		t.Fatalf("FormatRecoveryCode of nothing = %q", got)
	}
	if got := FormatRecoveryCode("ABCDEFG"); got != "ABCDE-FG" {
		t.Fatalf("FormatRecoveryCode of a short text = %q", got)
	}
}

func TestARecoveryCodeIsReadAsItIsTyped(t *testing.T) {
	canonical := "ABCDEFGHIJKLMNOPQRSTUVWXY"
	for _, typed := range []string{
		canonical, FormatRecoveryCode(canonical), strings.ToLower(canonical), strings.ToLower(FormatRecoveryCode(canonical)),
		" " + canonical + " ", "ABCDE FGHIJ KLMNO PQRST UVWXY", "abcde-FGHIJ-klmno-PQRST-uvwxy", "A-B-C-D-E-F-G-H-I-J-K-L-M-N-O-P-Q-R-S-T-U-V-W-X-Y",
	} {
		if got, ok := ParseRecoveryCode(typed); !ok || got != canonical {
			t.Errorf("ParseRecoveryCode(%q) = %q, %v; want %q", typed, got, ok, canonical)
		}
	}
	digits := "A2345-67ABC-DEFGH-IJKLM-NOPQR"
	if got, ok := ParseRecoveryCode(digits); !ok || got != "A234567ABCDEFGHIJKLMNOPQR" {
		t.Errorf("a code with the digits 2 to 7 = %q, %v", got, ok)
	}
	for name, typed := range map[string]string{
		"nothing":              "",
		"one character short":  canonical[:24],
		"one character long":   canonical + "A",
		"a zero":               "0" + canonical[1:],
		"a one":                "1" + canonical[1:],
		"an eight":             "8" + canonical[1:],
		"a nine":               "9" + canonical[1:],
		"an equals sign":       "=" + canonical[1:],
		"an underscore":        "_" + canonical[1:],
		"a letter of Cyrillic": "А" + canonical[1:],
		"a NUL":                "\x00" + canonical[1:],
		"a tab":                "\t" + canonical,
		"a new line":           canonical + "\n",
		"a lot of hyphens":     strings.Repeat("-", 100) + canonical,
		"a long text":          strings.Repeat("A", 1000),
		"only separators":      "- - - -",
		"a full width letter":  "Ａ" + canonical[1:],
	} {
		if got, ok := ParseRecoveryCode(typed); ok {
			t.Errorf("%s was accepted as %q", name, got)
		}
	}
}

func TestTheHashOfARecoveryCodeIsTheHMACOfTheAdministratorAndTheCode(t *testing.T) {
	master := randomMaster(t)
	k := newKeys(t, master)
	if !bytes.Equal(k.recovery, referenceHKDF(master, "limb/v1/recovery")) {
		t.Fatal("the recovery key is not HKDF-SHA256 with the info limb/v1/recovery")
	}
	want := referenceMAC(referenceHKDF(master, "limb/v1/recovery"), []byte{5, 'a', 'd', 'm', 'i', 'n', 3, 'a', 'b', 'c'})
	if got := k.RecoveryHash("admin", "abc"); !bytes.Equal(got, want) || len(got) != 32 {
		t.Fatalf("RecoveryHash = %x, want the HMAC-SHA256 of the framed parts %x", got, want)
	}
}

func TestTheHashOfARecoveryCodeDependsOnEverythingAndOnTheMasterKey(t *testing.T) {
	k := newKeys(t, randomMaster(t))
	base := k.RecoveryHash("admin-1", "ABCDEFGHIJKLMNOPQRSTUVWXY")
	for name, other := range map[string][]byte{
		"another administrator": k.RecoveryHash("admin-2", "ABCDEFGHIJKLMNOPQRSTUVWXY"),
		"another code":          k.RecoveryHash("admin-1", "ABCDEFGHIJKLMNOPQRSTUVWXZ"),
		"parts shifted":         k.RecoveryHash("admin-1A", "BCDEFGHIJKLMNOPQRSTUVWXY"),
		"another master key":    newKeys(t, randomMaster(t)).RecoveryHash("admin-1", "ABCDEFGHIJKLMNOPQRSTUVWXY"),
		"the key of the codes":  k.CodeHash(CodeBinding{TenantID: "admin-1", ID: "ABCDEFGHIJKLMNOPQRSTUVWXY"}, ""),
	} {
		if bytes.Equal(base, other) {
			t.Errorf("the hash is the same for %s", name)
		}
	}
	if !bytes.Equal(base, k.RecoveryHash("admin-1", "ABCDEFGHIJKLMNOPQRSTUVWXY")) {
		t.Fatal("the hash must be the same for the same input")
	}
	if bytes.Contains(base, []byte("ABCDE")) {
		t.Fatal("the hash contains the code")
	}
}

func FuzzParseRecoveryCode(f *testing.F) {
	for _, input := range []string{"", "ABCDEFGHIJKLMNOPQRSTUVWXY", "abcde-fghij-klmno-pqrst-uvwxy", "A2345 67ABC DEFGH IJKLM NOPQR", "0000000000000000000000000", "А", strings.Repeat("-", 70)} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		code, ok := ParseRecoveryCode(input)
		if !ok {
			if code != "" {
				t.Fatalf("a refused input gave %q", code)
			}
			return
		}
		if len(code) != RecoveryCodeLength || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
			t.Fatalf("%q was accepted as %q, which is not a code in the canonical form", input, code)
		}
		if again, parsed := ParseRecoveryCode(FormatRecoveryCode(code)); !parsed || again != code {
			t.Fatalf("the code %q does not survive being written in groups: %q, %v", code, again, parsed)
		}
		if len(strings.NewReplacer("-", "", " ", "").Replace(input)) != len(code) {
			t.Fatalf("%q was accepted as %q but has other characters than the code and its separators", input, code)
		}
	})
}
