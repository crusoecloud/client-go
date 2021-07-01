PREFIX?=$(shell pwd)

# TODO(template) update this to match your executable's name
NAME := templatecmd
# TODO(template) update this to point to your project
PKG := gitlab.com/crusoeenergy/templates/go/cmd/$(NAME)

BUILDDIR := ${PREFIX}/dist
# Set any default go build tags
BUILDTAGS :=

GOLANGCI_VERSION = v1.39.0
LSIF-GO_VERSION = latest
TOOLS_VERSION = latest

.PHONY: dev
dev: test build-deps lint ## Runs a build-deps, test, lint

.PHONY: ci
ci: test-ci build-deps lint lsif ## Runs test, build-deps, lint, lsif.

.PHONY: build-deps
build-deps: ## Install build dependencies
	@echo "==> $@"
	@cd /tmp; GO111MODULE=on go get github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_VERSION}
	@cd /tmp; GO111MODULE=on go get github.com/sourcegraph/lsif-go/cmd/lsif-go@${LSIF-GO_VERSION}

.PHONY: get-aliaslint
get-aliaslint:
	@echo "==> $@"
	@go get gitlab.com/crusoeenergy/tools/aliaslint@${TOOLS_VERSION}
	@go build -o aliaslint.so -buildmode=plugin gitlab.com/crusoeenergy/tools/aliaslint/plugin
	@go mod tidy

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
	@golangci-lint run ./...

.PHONY: lsif
lsif: ## Generates Language Server Index Format file. See https://lsif.dev/
	@echo "==> $@"
	@lsif-go

.PHONY: build
build: ## Builds the executable and places it in the build dir
	@go build -o ${BUILDDIR}/${NAME} ${PKG}

.PHONY: install
install: ## Builds and installs the executable on PATH
	@go install ${PKG}

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
