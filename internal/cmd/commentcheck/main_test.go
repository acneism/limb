package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func positions(t *testing.T, filename, src string) []string {
	t.Helper()
	found, err := checkSource(filename, []byte(src))
	if err != nil {
		t.Fatalf("checkSource: %v", err)
	}
	got := make([]string, 0, len(found))
	for _, v := range found {
		got = append(got, strconv.Itoa(v.line)+":"+strconv.Itoa(v.col))
	}
	return got
}

func TestCheckSource(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		src      string
		want     []string
	}{
		{
			name: "package doc allowed",
			src:  "// Package p does things.\npackage p\n",
		},
		{
			name: "exported func doc allowed",
			src:  "package p\n\n// Do does.\nfunc Do() {}\n",
		},
		{
			name: "unexported func doc flagged",
			src:  "package p\n\n// do does.\nfunc do() {}\n",
			want: []string{"3:1"},
		},
		{
			name: "comment in function body flagged",
			src:  "package p\n\nfunc Do() {\n\t// inner\n}\n",
			want: []string{"4:2"},
		},
		{
			name: "trailing line comment flagged",
			src:  "package p\n\nvar x = 1 // trailing\n",
			want: []string{"3:11"},
		},
		{
			name: "block comment flagged even as exported func doc",
			src:  "package p\n\n/* Do does. */\nfunc Do() {}\n",
			want: []string{"3:1"},
		},
		{
			name: "block comment in body flagged",
			src:  "package p\n\nfunc Do() {\n\t/* inner */\n}\n",
			want: []string{"4:2"},
		},
		{
			name: "go build allowed",
			src:  "//go:build linux\n\npackage p\n",
		},
		{
			name: "go embed above unexported var allowed",
			src:  "package p\n\nimport _ \"embed\"\n\n//go:embed a.txt\nvar a string\n",
		},
		{
			name: "normal line mixed into directive group flagged",
			src:  "package p\n\n//go:embed a.txt\n// normal\nvar a string\n",
			want: []string{"4:1"},
		},
		{
			name: "directive with space after slashes flagged",
			src:  "package p\n\n// go:generate x\nfunc f() {}\n",
			want: []string{"3:1"},
		},
		{
			name: "nolint with linter allowed",
			src:  "package p\n\nfunc f() {\n\t//nolint:gosec\n\t_ = 1\n}\n",
		},
		{
			name: "nolint with several linters allowed",
			src:  "package p\n\nfunc f() {\n\t_ = 1 //nolint:gosec,errcheck\n}\n",
		},
		{
			name: "nolint with explanation flagged",
			src:  "package p\n\nfunc f() {\n\t//nolint:gosec // reason\n\t_ = 1\n}\n",
			want: []string{"4:2"},
		},
		{
			name: "nolint with explanation inside exported doc group flagged",
			src:  "package p\n\n// Do does.\n//nolint:gosec // reason\nfunc Do() {}\n",
			want: []string{"4:1"},
		},
		{
			name: "strict nolint inside exported doc group allowed",
			src:  "package p\n\n// Do does.\n//nolint:gosec\nfunc Do() {}\n",
		},
		{
			name: "bare nolint inside exported doc group flagged",
			src:  "package p\n\n// Do does.\n//nolint\nfunc Do() {}\n",
			want: []string{"4:1"},
		},
		{
			name: "bare nolint flagged",
			src:  "package p\n\nfunc f() {\n\t//nolint\n\t_ = 1\n}\n",
			want: []string{"4:2"},
		},
		{
			name: "exported method of exported type allowed",
			src:  "package p\n\ntype T struct{}\n\n// M does.\nfunc (T) M() {}\n",
		},
		{
			name: "exported method of unexported type flagged",
			src:  "package p\n\ntype t struct{}\n\n// M does.\nfunc (t) M() {}\n",
			want: []string{"5:1"},
		},
		{
			name: "unexported method of exported type flagged",
			src:  "package p\n\ntype T struct{}\n\n// m does.\nfunc (T) m() {}\n",
			want: []string{"5:1"},
		},
		{
			name: "generic receiver with one parameter allowed",
			src:  "package p\n\ntype Set[T comparable] struct{}\n\n// Add adds.\nfunc (s *Set[T]) Add(v T) {}\n",
		},
		{
			name: "generic receiver with several parameters allowed",
			src:  "package p\n\ntype Pair[K comparable, V any] struct{}\n\n// Get gets.\nfunc (p *Pair[K, V]) Get() {}\n",
		},
		{
			name: "generic receiver of unexported type flagged",
			src:  "package p\n\ntype set[T comparable] struct{}\n\n// Add adds.\nfunc (s *set[T]) Add(v T) {}\n\ntype pair[K comparable, V any] struct{}\n\n// Get gets.\nfunc (p *pair[K, V]) Get() {}\n",
			want: []string{"5:1", "10:1"},
		},
		{
			name: "parenthesized receiver allowed",
			src:  "package p\n\ntype T struct{}\n\n// M does.\nfunc (*(T)) M() {}\n",
		},
		{
			name: "exported struct field docs",
			src:  "package p\n\n// T is.\ntype T struct {\n\t// A is.\n\tA int\n\t// b is.\n\tb int\n}\n",
			want: []string{"7:2"},
		},
		{
			name: "struct field trailing comment flagged",
			src:  "package p\n\n// T is.\ntype T struct {\n\tA int // trailing\n}\n",
			want: []string{"5:8"},
		},
		{
			name: "embedded struct field docs",
			src:  "package p\n\n// T is.\ntype T struct {\n\t// E is.\n\tE\n\t// f is.\n\t*f\n}\n",
			want: []string{"7:2"},
		},
		{
			name: "fields of unexported struct flagged",
			src:  "package p\n\ntype t struct {\n\t// A is.\n\tA int\n}\n",
			want: []string{"4:2"},
		},
		{
			name: "exported interface method docs",
			src:  "package p\n\n// I is.\ntype I interface {\n\t// M does.\n\tM()\n\t// n does.\n\tn()\n}\n",
			want: []string{"7:2"},
		},
		{
			name: "embedded interface doc flagged",
			src:  "package p\n\n// I is.\ntype I interface {\n\t// E is.\n\tE\n}\n",
			want: []string{"5:2"},
		},
		{
			name: "grouped const with exported name allowed",
			src:  "package p\n\n// Group of consts.\nconst (\n\tA = 1\n\tb = 2\n)\n",
		},
		{
			name: "grouped const without exported name flagged",
			src:  "package p\n\n// Group of consts.\nconst (\n\ta = 1\n\tb = 2\n)\n",
			want: []string{"3:1"},
		},
		{
			name: "spec doc inside group follows its own names",
			src:  "package p\n\nconst (\n\t// A is.\n\tA = 1\n\t// b is.\n\tb = 2\n)\n",
			want: []string{"6:2"},
		},
		{
			name: "exported var and type docs allowed",
			src:  "package p\n\n// V is.\nvar V = 1\n\n// T is.\ntype T int\n",
		},
		{
			name: "unexported var and type docs flagged",
			src:  "package p\n\n// v is.\nvar v = 1\n\n// t is.\ntype t int\n",
			want: []string{"3:1", "6:1"},
		},
		{
			name: "import doc flagged",
			src:  "package p\n\n// fmt is used.\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n",
			want: []string{"3:1"},
		},
		{
			name: "blank identifier doc flagged",
			src:  "package p\n\n// blank.\nvar _ = 1\n",
			want: []string{"3:1"},
		},
		{
			name:     "output block in example of test file allowed",
			filename: "p_test.go",
			src:      "package p\n\nfunc ExampleDo() {\n\tprintln(1)\n\t// Output: 1\n}\n",
		},
		{
			name:     "multi line output block allowed",
			filename: "p_test.go",
			src:      "package p\n\nfunc ExampleDo() {\n\tprintln(1)\n\t// Output:\n\t// 1\n\t// 2\n}\n",
		},
		{
			name:     "unordered output block allowed",
			filename: "p_test.go",
			src:      "package p\n\nfunc Example_suffix() {\n\t// Unordered output:\n\t// 1\n}\n",
		},
		{
			name:     "plain Example func name allowed",
			filename: "p_test.go",
			src:      "package p\n\nfunc Example() {\n\t// Output: 1\n}\n",
		},
		{
			name:     "output marker not at group start flagged",
			filename: "p_test.go",
			src:      "package p\n\nfunc ExampleDo() {\n\t// note\n\t// Output: 1\n}\n",
			want:     []string{"4:2", "5:2"},
		},
		{
			name:     "other comment in example flagged",
			filename: "p_test.go",
			src:      "package p\n\nfunc ExampleDo() {\n\t// note\n\n\t// Output: 1\n}\n",
			want:     []string{"4:2"},
		},
		{
			name:     "output block in test func flagged",
			filename: "p_test.go",
			src:      "package p\n\nfunc TestDo() {\n\t// Output: 1\n}\n",
			want:     []string{"4:2"},
		},
		{
			name:     "output block in lowercase example name flagged",
			filename: "p_test.go",
			src:      "package p\n\nfunc Examplefoo() {\n\t// Output: 1\n}\n",
			want:     []string{"4:2"},
		},
		{
			name:     "output block in example method flagged",
			filename: "p_test.go",
			src:      "package p\n\ntype T struct{}\n\nfunc (T) ExampleDo() {\n\t// Output: 1\n}\n",
			want:     []string{"6:2"},
		},
		{
			name:     "output text outside example body flagged",
			filename: "p_test.go",
			src:      "package p\n\n// Output: 1\nvar x = 1\n\nfunc ExampleDo() {}\n",
			want:     []string{"3:1"},
		},
		{
			name:     "output block in non test file flagged",
			filename: "p.go",
			src:      "package p\n\nfunc ExampleDo() {\n\t// Output: 1\n}\n",
			want:     []string{"4:2"},
		},
		{
			name: "generated file skipped",
			src:  "// Code generated by tool; DO NOT EDIT.\n\npackage p\n\n// bad\nfunc f() {\n\t// bad\n}\n",
		},
		{
			name: "multiple violations sorted by position",
			src:  "package p\n\nvar a = 1 // one\n\nfunc f() {\n\t// two\n}\n",
			want: []string{"3:11", "6:2"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filename := tc.filename
			if filename == "" {
				filename = "p.go"
			}
			got := positions(t, filename, tc.src)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("violations = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCheckSourceParseError(t *testing.T) {
	_, err := checkSource("broken.go", []byte("package"))
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "broken.go") {
		t.Fatalf("error %q does not mention the file path", err)
	}
}

func TestViolationString(t *testing.T) {
	v := violation{path: "a/b.go", line: 3, col: 7}
	want := "a/b.go:3:7: comment not allowed"
	if got := v.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func runCapture(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

const (
	cleanSource    = "package p\n\n// Do does.\nfunc Do() {}\n"
	violatingFirst = "package p\n\n// bad\nfunc f() {}\n"
)

func TestRunWalkSkipsAndSorts(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"z.go":                violatingFirst,
		"a.go":                cleanSource,
		"sub/b.go":            "package p\n\nvar a = 1 // x\n\nvar b = 2 // y\n",
		"sub/b_test.go":       violatingFirst,
		"sub/notes.txt":       "// not go",
		"testdata/t.go":       violatingFirst,
		"sub/testdata/t.go":   violatingFirst,
		"vendor/v.go":         violatingFirst,
		".hidden/h.go":        violatingFirst,
		"_ignored/i.go":       violatingFirst,
		"sub/.hidden/deep.go": violatingFirst,
	})
	t.Chdir(root)

	code, stdout, stderr := runCapture(".")
	want := strings.Join([]string{
		"sub/b.go:3:11: comment not allowed",
		"sub/b.go:5:11: comment not allowed",
		"sub/b_test.go:3:1: comment not allowed",
		"z.go:3:1: comment not allowed",
		"",
	}, "\n")
	if code != exitViolations || stdout != want || stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q, want code=1 stdout=%q", code, stdout, stderr, want)
	}

	code, stdout, _ = runCapture()
	if code != exitViolations || stdout != want {
		t.Fatalf("default root: code=%d stdout=%q", code, stdout)
	}
}

func TestRunDeduplicatesOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"sub/x.go": violatingFirst})
	t.Chdir(root)

	code, stdout, _ := runCapture(".", "sub")
	want := "sub/x.go:3:1: comment not allowed\n"
	if code != exitViolations || stdout != want {
		t.Fatalf("code=%d stdout=%q, want %q", code, stdout, want)
	}
}

func TestRunClean(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"a.go": cleanSource, "sub/b.go": cleanSource})
	t.Chdir(root)

	code, stdout, stderr := runCapture(".")
	if code != exitClean || stdout != "" || stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestRunExplicitHiddenRootIsChecked(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{".cfg/x.go": violatingFirst})
	t.Chdir(root)

	code, stdout, _ := runCapture(".cfg")
	if code != exitViolations || stdout != ".cfg/x.go:3:1: comment not allowed\n" {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}

func TestRunPathOutsideWorkingDirectory(t *testing.T) {
	target := t.TempDir()
	writeFiles(t, target, map[string]string{"x.go": violatingFirst})
	t.Chdir(t.TempDir())

	code, stdout, _ := runCapture(target)
	if code != exitViolations {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	if !strings.HasPrefix(stdout, "..") || !strings.HasSuffix(stdout, "x.go:3:1: comment not allowed\n") {
		t.Fatalf("stdout=%q, want a relative path ending in x.go", stdout)
	}
}

func TestRunParseErrorExitsWithFailure(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"bad.go": "package",
		"x.go":   violatingFirst,
	})
	t.Chdir(root)

	code, stdout, stderr := runCapture(".")
	if code != exitFailure {
		t.Fatalf("code=%d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr, "bad.go") {
		t.Fatalf("stderr=%q does not mention bad.go", stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout=%q, want empty", stdout)
	}
}

func TestRunUsageErrors(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"a.go": cleanSource})
	t.Chdir(root)

	for _, args := range [][]string{
		{"missing"},
		{"a.go"},
		{"-h"},
		{".", "-x"},
	} {
		code, stdout, stderr := runCapture(args...)
		if code != exitFailure || stdout != "" || stderr == "" {
			t.Errorf("args %v: code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestRunUnreadableWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	gone := filepath.Join(root, "gone")
	if err := os.Mkdir(gone, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Skipf("cannot remove working directory: %v", err)
	}

	code, _, stderr := runCapture()
	if code != exitFailure || stderr == "" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}
