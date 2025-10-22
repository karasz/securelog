# Makefile for SecureLog - Dual MAC Secure Logging System
# https://github.com/karasz/securelog

.PHONY: all build test lint fmt vet revive clean install help spell

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet
GOMOD=$(GOCMD) mod

# Binary name
BINARY_NAME=securelog

# Build flags
LDFLAGS=-ldflags "-s -w"

# Default target
all: fmt vet lint test build

## help: Show this help message
help:
	@echo 'Usage:'
	@echo '  make [target]'
	@echo ''
	@echo 'Targets:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## build: Build the project
build:
	@echo "Building..."
	$(GOBUILD) $(LDFLAGS) -v ./...

## test: Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	@echo ""
	@echo "Coverage summary:"
	@$(GOCMD) tool cover -func=coverage.out | tail -1

## test-short: Run tests without race detector (faster)
test-short:
	@echo "Running tests (short)..."
	$(GOTEST) -v ./...

## coverage: Run tests and show coverage report in browser
coverage: test
	@echo "Opening coverage report in browser..."
	$(GOCMD) tool cover -html=coverage.out

## bench: Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	@$(GOFMT) ./...
	@echo "Code formatted successfully"

## vet: Run go vet
vet:
	@echo "Running go vet..."
	@$(GOVET) ./...
	@echo "go vet passed"

## lint: Run linters (revive + staticcheck)
lint: revive staticcheck

## revive: Run revive linter
revive:
	@echo "Running revive..."
	@if ! command -v revive > /dev/null 2>&1; then \
		if [ -f $(HOME)/go/bin/revive ]; then \
			$(HOME)/go/bin/revive -config revive.toml -formatter friendly -exclude proto/... ./...; \
		else \
			echo "Installing revive..." && $(GOGET) github.com/mgechev/revive@latest && $(HOME)/go/bin/revive -config revive.toml -formatter friendly -exclude proto/... ./...; \
		fi \
	else \
		revive -config revive.toml -formatter friendly -exclude proto/... ./...; \
	fi

## staticcheck: Run staticcheck
staticcheck:
	@echo "Running staticcheck..."
	@if ! command -v staticcheck > /dev/null 2>&1; then \
		if [ -f $(HOME)/go/bin/staticcheck ]; then \
			$(HOME)/go/bin/staticcheck ./...; \
		else \
			echo "Installing staticcheck..." && $(GOGET) honnef.co/go/tools/cmd/staticcheck@latest && $(HOME)/go/bin/staticcheck ./...; \
		fi \
	else \
		staticcheck ./...; \
	fi

## spell: Run spell checker (cspell)
spell:
	@echo "Running spell checker..."
	@if ! command -v cspell > /dev/null 2>&1; then \
		echo "cspell not found. Install with: npm install -g cspell"; \
		echo "Or use: npx cspell"; \
		exit 1; \
	fi
	@cspell --no-progress "**/*.{go,md,txt,toml,yml,yaml}" --exclude "vendor/**" --exclude "*.log"

## check: Run all checks (fmt, vet, lint, spell, test)
check: fmt vet lint spell test
	@echo ""
	@echo "✓ All checks passed!"

## clean: Remove build artifacts and test files
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME)
	@rm -f coverage.out
	@rm -rf testdata/tmp*
	@$(GOCMD) clean -testcache
	@echo "Cleaned successfully"

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	@$(GOMOD) download
	@$(GOMOD) tidy

## deps-update: Update dependencies
deps-update:
	@echo "Updating dependencies..."
	@$(GOGET) -u ./...
	@$(GOMOD) tidy

## install-tools: Install development tools
install-tools:
	@echo "Installing development tools..."
	@$(GOGET) github.com/mgechev/revive@latest
	@$(GOGET) honnef.co/go/tools/cmd/staticcheck@latest
	@$(GOGET) github.com/securego/gosec/v2/cmd/gosec@latest
	@echo ""
	@echo "Go tools installed successfully"
	@echo ""
	@echo "To install cspell (spell checker), run:"
	@echo "  npm install -g cspell"
	@echo "Or use npx: npx cspell"

## verify: Verify dependencies and check for issues
verify:
	@echo "Verifying dependencies..."
	@$(GOMOD) verify
	@echo "Dependencies verified"

## security: Run security checks with gosec
security:
	@echo "Running security checks..."
	@if ! command -v gosec > /dev/null 2>&1; then \
		if [ -f $(HOME)/go/bin/gosec ]; then \
			$(HOME)/go/bin/gosec -quiet ./...; \
		else \
			echo "Installing gosec..." && $(GOGET) github.com/securego/gosec/v2/cmd/gosec@latest && $(HOME)/go/bin/gosec -quiet ./...; \
		fi \
	else \
		gosec -quiet ./...; \
	fi

## ci: Run CI pipeline (fmt, vet, lint, spell, test)
ci: deps verify fmt vet lint spell test
	@echo ""
	@echo "✓ CI pipeline completed successfully!"

## doc: Generate and serve documentation
doc:
	@echo "Starting documentation server at http://localhost:6060"
	@which godoc > /dev/null || (echo "Installing godoc..." && $(GOGET) golang.org/x/tools/cmd/godoc@latest)
	@godoc -http=:6060

.DEFAULT_GOAL := help
