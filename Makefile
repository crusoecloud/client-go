# Tool pins, execution, and workflow ordering live in mise.toml.
ifneq ($(origin BUILDTAGS),undefined)
export BUILDTAGS
endif
ifneq ($(origin GOLANGCI_VERSION),undefined)
export GOLANGCI_VERSION
endif

.PHONY: dev ci build-deps precommit test test-ci lint help

dev: ## Run tests and lint
	@mise run dev

ci: ## Run module, coverage, and lint checks
	@mise run test:all

build-deps: ## Install project tools
	@mise install

precommit: ## Tidy modules and apply lint fixes
	@mise run precommit

test: ## Run the race tests
	@mise run go:test:race

test-ci: ## Check modules and preserve atomic race coverage reports
	@mise run test:checks

lint: ## Run lint checks
	@mise run lint:all

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' Makefile | sort
