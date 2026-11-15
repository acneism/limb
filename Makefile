.PHONY: fmt lint test cover vuln comments check

fmt:
	golangci-lint fmt

lint:
	golangci-lint run

test:
	go test -race -count=1 ./...

cover:
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vuln:
	govulncheck ./...

comments:
	go run ./internal/cmd/commentcheck .
	if grep -rnE '^[[:space:]]*#' --include='*.yml' --include='*.yaml' --include=Makefile --include=.gitignore --exclude-dir=.git . ; then exit 1; fi

check: comments lint test vuln
