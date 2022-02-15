PREFIX?=$(shell pwd)

GOLANGCI_VERSION = v1.41.1
TOOLS_VERSION = v0.1.1

.PHONY: dev
dev: test build-deps lint ## Runs a , test, lint

.PHONY: ci
ci: test-ci build-deps lint ## Runs test, lint

.PHONY: build-deps
build-deps: ## Install build dependencies
	@echo "==> $@"
	@GO111MODULE=on go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_VERSION}

.PHONY: get-aliaslint
get-aliaslint:
	@echo "==> $@"
	@go mod download gitlab.com/crusoeenergy/tools@${TOOLS_VERSION}
	@cd `go env GOMODCACHE`/gitlab.com/crusoeenergy/tools@${TOOLS_VERSION}; go build -o ${PREFIX}/aliaslint.so -buildmode=plugin aliaslint/plugin/aliaslint.go

.PHONY: precommit
precommit: ## runs various formatters that will be checked by linter (but can/should be automatic in your editor)
	@echo "==> $@"
	@go mod tidy
	@golangci-lint run --fix ./...

.PHONY: test
test: ## Runs the go tests.
	@echo "==> $@"
	@go test -tags "$(BUILDTAGS)" -cover -race -v ./...

.PHONY: test-ci
test-ci: ## Runs the go tests with additional options for a CI environment
	@echo "==> $@"
	@go mod tidy
	@git diff --exit-code go.mod go.sum # fail if go.mod is not tidy
	@go test -tags "$(BUILDTAGS)" -coverprofile=coverage.out -race -v ./...
	@go tool cover -func=coverage.out

.PHONY: lint
lint: get-aliaslint ## Verifies `golangci-lint` passes
	@echo "==> $@"
	@golangci-lint version
	@golangci-lint run ./... --skip-dirs "swagger"

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
