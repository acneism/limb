# limb

limb is an authentication library for Go with a built-in web admin panel.
It works with PostgreSQL, MySQL/MariaDB and Oracle through `database/sql`.

**Status:** early development, not ready for use.

## License

Apache 2.0, see [LICENSE](LICENSE).

## Development

Requirements: Go 1.26 or newer, golangci-lint v2 and govulncheck on `PATH`.

Run every check (lint, tests with the race detector, vulnerability scan) with:

```sh
make check
```

The tests of the SQL store and the end-to-end tests of the library need a database. Every database engine has a variable of its own, and the tests run on each engine whose variable holds a DSN, as a subtest named after the engine; they are skipped when no variable is set. `LIMB_TEST_POSTGRES_DSN` is the variable of PostgreSQL, for example `postgres://user:password@localhost:5432/limb_test?sslmode=disable`. The user must be allowed to create and drop tables; every test works in tables with a prefix of its own and removes them afterwards. CI runs these tests against PostgreSQL 15 and 18, one database in every job, and fails a job in which a test is skipped.

Comment policy: code carries no comments except godoc on exported identifiers, tool directives (`//go:...` and `//nolint:<linter>` without explanation) and `// Output:` blocks in test examples. Inline, trailing and block comments, commented-out code, license headers and TODOs are not used, and the same rule applies to YAML, Makefile and `.gitignore` files. Names and small functions are the documentation.
