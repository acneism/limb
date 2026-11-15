package limb_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestLibraryLinksNoDriversAndNoPhoneMetadata(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{.ImportPath}}", ".").Output()
	if err != nil {
		t.Skipf("go list is not available: %v", err)
	}
	banned := []string{"jackc/pgx", "lib/pq", "go-sql-driver", "sijms/go-ora", "nyaruka/phonenumbers"}
	for _, path := range strings.Fields(string(out)) {
		for _, name := range banned {
			if strings.Contains(path, name) {
				t.Fatalf("the library must not link %s, but it imports %s: drivers belong to the application and phone numbers to identifier/phone", name, path)
			}
		}
	}
}
