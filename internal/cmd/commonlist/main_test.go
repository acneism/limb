package main

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestFilter(t *testing.T) {
	cases := []struct {
		name   string
		source string
		min    int
		want   []string
	}{
		{"empty input", "", 8, nil},
		{"keeps entries of the minimum length", "abcdefgh\nabcdefg\n", 8, []string{"abcdefgh"}},
		{"lower cases", "PassWord1\n", 8, []string{"password1"}},
		{"sorts and removes duplicates", "zzzzzzzz\naaaaaaaa\nZZZZZZZZ\naaaaaaaa\n", 8, []string{"aaaaaaaa", "zzzzzzzz"}},
		{"trims white space and carriage returns", "  trimmed-1  \r\nwindows-1\r\n", 8, []string{"trimmed-1", "windows-1"}},
		{"drops empty lines", "\n\n  \nabcdefgh\n", 8, []string{"abcdefgh"}},
		{"normalizes with NFKC before counting", "\ufb01\ufb01\ufb01\ufb01\n", 8, []string{"fifififi"}},
		{"counts characters, not bytes", "пароль-12\nпароль\n", 8, []string{"пароль-12"}},
		{"drops invalid UTF-8", "valid-password\nbroken-\xff-password\n", 8, []string{"valid-password"}},
		{"drops control characters", "with\x00nul-byte\nwith\ttab-inside\nplain-text\n", 8, []string{"plain-text"}},
		{"honours another minimum", "abc\nabcd\nabcde\n", 4, []string{"abcd", "abcde"}},
		{"no trailing newline", "last-entry", 8, []string{"last-entry"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := filter(strings.NewReader(tc.source), tc.min)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("filter = %q, want %q", got, tc.want)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("disk on fire")
}

func TestFilterReportsReadErrors(t *testing.T) {
	if _, err := filter(failingReader{}, 8); err == nil {
		t.Fatal("a read error must be reported")
	}
	if _, err := filter(strings.NewReader(strings.Repeat("a", maxLineSize+1)), 8); err == nil {
		t.Fatal("a line beyond the limit must be reported")
	}
}

func TestRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, strings.NewReader("Beta-pass1\nalpha-pass\nBETA-PASS1\nshort\n"), &stdout, &stderr); code != exitClean {
		t.Fatalf("exit code %d, stderr %q", code, stderr.String())
	}
	if got, want := stdout.String(), "alpha-pass\nbeta-pass1\n"; got != want {
		t.Fatalf("output %q, want %q", got, want)
	}
	stdout.Reset()
	if code := run([]string{"-min", "5"}, strings.NewReader("short\nlong-enough\n"), &stdout, &stderr); code != exitClean || stdout.String() != "long-enough\nshort\n" {
		t.Fatalf("exit code %d, output %q", code, stdout.String())
	}
}

func TestRunFailures(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-nope"}, strings.NewReader(""), &stdout, &stderr); code != exitUsage {
		t.Fatalf("an unknown flag must give the usage exit code, got %d", code)
	}
	if code := run([]string{"extra"}, strings.NewReader(""), &stdout, &stderr); code != exitUsage || !strings.Contains(stderr.String(), "usage") {
		t.Fatalf("an argument must give the usage exit code, got %d, %q", code, stderr.String())
	}
	if code := run(nil, failingReader{}, &stdout, &stderr); code != exitFailure {
		t.Fatalf("a read error must give the failure exit code, got %d", code)
	}
	if code := run(nil, strings.NewReader("long-enough-1\n"), failingWriter{}, &stderr); code != exitFailure {
		t.Fatalf("a write error must give the failure exit code, got %d", code)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk is full")
}
