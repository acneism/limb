package limb

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/acneism/limb/internal/memstore"
)

func FuzzCommandLine(f *testing.F) {
	a, err := NewWithStore(memstore.New(), []byte(testKey), WithAutoMigrate(), WithLogger(discardingLogger()))
	if err != nil {
		f.Fatal(err)
	}
	a.hasher = newHasher(f, weakParams)
	for _, seed := range []struct{ args, stdin string }{
		{"help", ""},
		{"", ""},
		{"admin\x00list", ""},
		{"admin\x00create\x00--login\x00root\x00--password-stdin", typedPassword + "\n"},
		{"admin\x00create\x00root\x00--password-stdin", typedPassword},
		{"admin\x00create\x00--login=Root\x00--password-stdin", "short\n"},
		{"admin\x00reset-password\x00root\x00--password-stdin", typedPassword + " 2\r\n"},
		{"admin\x00disable\x00--login\x00root", ""},
		{"admin\x00enable\x00root", ""},
		{"admin\x00reset-totp\x00root", ""},
		{"admin\x00delete\x00--\x00-root", ""},
		{"admin\x00delete\x00--login", ""},
		{"admin\x00create\x00--password-stdin\x00--login\x00роот", typedPassword},
		{"migrate", ""},
		{"cleanup", ""},
		{"migrate\x00now", ""},
		{"admin\x00create\x00" + strings.Repeat("a", 200) + "\x00--password-stdin", strings.Repeat("x", 5000)},
	} {
		f.Add(seed.args, seed.stdin)
	}
	f.Fuzz(func(t *testing.T, joined, stdin string) {
		var stdout, stderr bytes.Buffer
		code := a.RunCommandInput(context.Background(), strings.NewReader(stdin), strings.Split(joined, "\x00"), &stdout, &stderr)
		switch {
		case code < 0 || code > 2:
			t.Fatalf("the exit code is %d", code)
		case code == 0 && stderr.Len() != 0:
			t.Fatalf("a command that was done wrote to stderr: %q", stderr.String())
		case code != 0 && stdout.Len() != 0 && !strings.HasPrefix(stdout.String(), "commands:"):
			t.Fatalf("a command that failed wrote to stdout: %q", stdout.String())
		case code == 2 && !strings.Contains(stderr.String(), "commands:"):
			t.Fatalf("a command that was not understood did not show the usage: %q", stderr.String())
		}
		line := strings.TrimRight(strings.SplitN(stdin, "\n", 2)[0], "\r")
		if len(line) >= 12 && (strings.Contains(stdout.String(), line) || strings.Contains(stderr.String(), line)) {
			t.Fatalf("the output holds the password that was given: %q %q", stdout.String(), stderr.String())
		}
	})
}
