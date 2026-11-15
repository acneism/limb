package password

import (
	"os"
	"strings"
	"testing"
)

func TestCommonListIsEmbedded(t *testing.T) {
	set := commonSet()
	if len(set) < 9000 {
		t.Fatalf("the embedded list has only %d entries", len(set))
	}
	for _, entry := range []string{"password", "123456", "qwerty", "unbelievable"} {
		if _, found := set[entry]; !found {
			t.Errorf("%q is missing from the list", entry)
		}
	}
	for entry := range set {
		if entry != strings.ToLower(strings.TrimSpace(entry)) || entry == "" {
			t.Fatalf("entry %q is not stored in normalized form", entry)
		}
	}
}

func TestIsCommon(t *testing.T) {
	for _, password := range []string{"password", "PASSWORD", "PassWord", "123456", "unbelievable"} {
		if !IsCommon(password) {
			t.Errorf("%q must be reported as common", password)
		}
	}
	for _, password := range []string{"", "correct horse battery staple", "unbelievable ", "p4ssw0rd-9c1e"} {
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
