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
- After opening or editing a pull request, read its body back (for example with `gh api repos/acneism/limb/pulls/<number> --jq .body`) and remove any footer a tool appended automatically.
- Commit signing is off.

Once per clone:

```bash
git config user.name acneism
git config user.email 122925114+acneism@users.noreply.github.com
git config commit.gpgsign false
```

Before every push, run this command and check its output:

```bash
git log --format='%an <%ae> | %cn <%ce>%n%B' origin/main..HEAD
```

- Every author and committer is `acneism`.
- There are no `Co-Authored-By` or `Claude-Session` trailers, no "Generated with" footers and no links to sessions.
- Naming the `CLAUDE.md` file in a commit message is fine.

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

- Check `golangci-lint version`: it must report v2.15.0 built with go1.27 or newer. If an older binary shadows it, put `$(go env GOPATH)/bin` first in `PATH`.
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

Every change:

- New behaviour is covered by unit tests; storage changes also by integration tests on every supported database in CI and by the storage compatibility suite; normalization, validation and token parsing also by fuzz tests.
- All tests pass with the race detector and core coverage stays at or above 85%.
- `make check` is clean (govulncheck may run in CI only) and new exported API has godoc.
- The team lead has accepted the change after reviewing it against the OWASP ASVS checklist.

Release v1.0 also needs:

- README in English and Russian with a quick start, and runnable examples.
- A full OWASP ASVS 5.0 level 2 review of authentication, sessions and tokens with no open high-severity findings.
