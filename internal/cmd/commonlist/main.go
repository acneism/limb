package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/acneism/limb/internal/password"
)

const (
	exitClean   = 0
	exitFailure = 1
	exitUsage   = 2
	maxLineSize = 1 << 20
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("commonlist", flag.ContinueOnError)
	flags.SetOutput(stderr)
	minLength := flags.Int("min", password.FloorMinLength, "shortest entry to keep, in characters")
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: commonlist [-min length] < source > list")
		return exitUsage
	}
	entries, err := filter(stdin, *minLength)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitFailure
	}
	out := bufio.NewWriter(stdout)
	for _, entry := range entries {
		_, _ = out.WriteString(entry + "\n")
	}
	if err = out.Flush(); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitFailure
	}
	return exitClean
}

func filter(source io.Reader, minLength int) ([]string, error) {
	kept := map[string]struct{}{}
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)
	for scanner.Scan() {
		line := scanner.Text()
		if !utf8.ValidString(line) {
			continue
		}
		entry := strings.ToLower(password.Normalize(strings.TrimSpace(line)))
		if utf8.RuneCountInString(entry) < minLength || strings.IndexFunc(entry, unicode.IsControl) >= 0 {
			continue
		}
		kept[entry] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(kept)), nil
}
