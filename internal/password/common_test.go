package password

import (
	"os"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestCommonListIsEmbedded(t *testing.T) {
	entries := commonEntries()
	if len(entries) < 38000 {
		t.Fatalf("the embedded list has only %d entries", len(entries))
	}
	for _, entry := range []string{"password", "12345678", "iloveyou", "football", "unbelievable"} {
		if _, found := slices.BinarySearch(entries, entry); !found {
			t.Errorf("%q is missing from the list", entry)
		}
	}
}

func TestCommonListIsInCanonicalForm(t *testing.T) {
	if !strings.HasSuffix(commonList, "\n") || strings.Contains(commonList, "\n\n") {
		t.Fatal("the list must have one entry per line and end with a newline")
	}
	entries := commonEntries()
	if !slices.IsSorted(entries) {
		t.Fatal("the list must be sorted, lookups use binary search")
	}
	for n, entry := range entries {
		switch {
		case n > 0 && entry == entries[n-1]:
			t.Fatalf("entry %q is repeated", entry)
		case !utf8.ValidString(entry), entry != strings.ToLower(Normalize(entry)):
			t.Fatalf("entry %q is not valid lower case NFKC text", entry)
		case utf8.RuneCountInString(entry) < FloorMinLength:
			t.Fatalf("entry %q is shorter than %d characters", entry, FloorMinLength)
		case strings.IndexFunc(entry, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) && r != ' ' }) >= 0:
			t.Fatalf("entry %q has control or white space characters", entry)
		case entry != strings.TrimSpace(entry):
			t.Fatalf("entry %q has white space around it", entry)
		}
	}
}

func TestIsCommon(t *testing.T) {
	for _, password := range []string{"password", "PASSWORD", "PassWord", "\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44", "12345678", "unbelievable", "UnBelievable"} {
		if !IsCommon(password) {
			t.Errorf("%q must be reported as common", password)
		}
	}
	for _, password := range []string{"", "correct horse battery staple", "password ", " password", "p4ssw0rd-9c1e", "123456", "qwerty"} {
		if IsCommon(password) {
			t.Errorf("%q must not be reported as common", password)
		}
	}
}

func TestListLicenseTravelsWithTheList(t *testing.T) {
	text, err := os.ReadFile("data/LICENSE")
	if err != nil {
		t.Fatalf("the license of the embedded list is missing: %v", err)
	}
	if !strings.Contains(string(text), "MIT License") || !strings.Contains(string(text), "Daniel Miessler") {
		t.Fatalf("data/LICENSE is not the SecLists license:\n%s", text)
	}
}

func TestListProvenanceIsDocumented(t *testing.T) {
	text, err := os.ReadFile("data/README.md")
	if err != nil {
		t.Fatalf("the description of the list is missing: %v", err)
	}
	for _, want := range []string{"xato-net-10-million-passwords-100000.txt", "180c2d55afa7aab8b18b7552f82dd0c92cc4ede5", "internal/cmd/commonlist"} {
		if !strings.Contains(string(text), want) {
			t.Errorf("data/README.md does not mention %q", want)
		}
	}
}
