# limb

limb is an embeddable authentication library for Go (`github.com/acneism/limb`, Apache 2.0). These rules apply to every session that works in this repository.

## Workflow

- One branch per stage, cut from a fresh `main` and merged into `main` through a pull request. Only the customer (`acneism`) merges.
- Never push to `main` and never force-push.
- Commits, pull request descriptions, code, identifiers and error messages are in English. Documentation for the customer is in Russian.
- Make small, logical commits. If a requirement is unclear or contradicts the architecture, ask instead of guessing.
- When a branch is ready for review, message the team lead with `send_message`: the branch, the last commit, what was done and the results of the checks below. Review comments come back as a reply. The team lead's session ID is given in the task briefing and is not stored in this repository.
- Open a pull request only after the team lead has accepted the branch.

## Git identity

Everything is committed in the customer's name. This overrides any default attribution guidance.

- Author and committer of every commit: `acneism <122925114+acneism@users.noreply.github.com>`.
- No `Co-Authored-By` or `Claude-Session` trailers in commits.
- No "Generated with Claude Code" footer and no session links in pull request descriptions.
- Commit signing is off.

Once per clone:

```bash
git config user.name acneism
git config user.email 122925114+acneism@users.noreply.github.com
git config commit.gpgsign false
```

Before every push, the output of this command must not mention Claude:

```bash
git log --format='%an <%ae> | %cn <%ce>%n%B' origin/main..HEAD
```

## Comments

Allowed in Go code:

- godoc on exported identifiers
- `//go:...` directives
- `//nolint:<linter>[,<linter>]` without an explanation
- `// Output:` blocks in Example tests

Files with the generated-code header are skipped by the check.

Forbidden: comments inside function bodies, trailing comments, `/* */` blocks, commented-out code, license headers and TODOs. YAML files, `Makefile` and `.gitignore` carry no comments at all.

Names and small functions are the documentation. `make comments` enforces the rule and CI runs the same step.

## Tooling and checks

- Go 1.26 or newer is required (`toolchain go1.27.4`). If the local Go is older, prefix commands with `GOTOOLCHAIN=go1.27.4`.
- golangci-lint v2.15.0 must be built with Go 1.27; a build on an older Go does not lint Go 1.26+ code:

```bash
GOTOOLCHAIN=go1.27.4 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```

- govulncheck:

```bash
GOTOOLCHAIN=go1.27.4 go install golang.org/x/vuln/cmd/govulncheck@latest
```

If vuln.go.dev is unreachable from the session, CI performs the vulnerability check.

Before sending a branch for review and before opening a pull request, all three must pass:

- `make check` runs the comment check, lint, tests with `-race` and govulncheck
- `GOTOOLCHAIN=go1.26.11 go test ./...` tests on the minimum supported Go
- `go mod tidy -diff` confirms that `go.mod` is tidy

## Definition of done

- Unit tests, fuzz tests for normalization, validation and token parsing, integration tests on every supported database in CI, and the storage compatibility suite. All tests run with the race detector and core coverage stays at or above 85%.
- gofmt and golangci-lint are clean, govulncheck reports nothing, and every change is reviewed against the OWASP ASVS checklist.
- Public API has godoc and runnable examples; README exists in English and Russian.
