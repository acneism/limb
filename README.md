# limb

limb is an authentication library for Go with a built-in web admin panel.
It works with PostgreSQL, MySQL/MariaDB and Oracle through `database/sql`.

**Status:** early development, not ready for use.

## License

Apache 2.0, see [LICENSE](LICENSE).

## Development

Requirements: Go 1.26 or newer, golangci-lint v2 and govulncheck on `PATH`.

Run every check (comment policy, lint, tests with the race detector, vulnerability scan) with:

```sh
make check
```

Comment policy: code carries no comments except godoc on exported identifiers, tool directives (`//go:...` and `//nolint:<linter>` without explanation) and `// Output:` blocks in test examples. Inline, trailing and block comments, commented-out code, license headers and TODOs are rejected by `make comments`, and the same rule applies to YAML, Makefile and `.gitignore` files. Names and small functions are the documentation.
