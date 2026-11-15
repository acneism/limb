package identifier_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestPackageDoesNotLinkPhoneMetadata(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{.ImportPath}}", ".").Output()
	if err != nil {
		t.Skipf("go list is not available: %v", err)
	}
	for _, path := range strings.Fields(string(out)) {
		if strings.Contains(path, "nyaruka/phonenumbers") {
			t.Fatalf("package identifier must not depend on the phone number library, but imports %s", path)
		}
	}
}
