TAILWIND ?= tailwindcss

.PHONY: fmt lint test cover vuln check css

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

check: lint test vuln

css:
	$(TAILWIND) --input internal/adminui/styles/input.css --output internal/adminui/static/admin.css --minify
