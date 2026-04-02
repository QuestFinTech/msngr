.DEFAULT_GOAL := help
.PHONY: help build release run init clean test test-cover lint vet fmt check

VERSION ?= 0.2.0
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD)"

RUNDIR  := run

## help: Show this help message
help:
	@echo "MSNGR — Mail Secure Network Gateway Relay"
	@echo ""
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'
	@echo ""

# --- Build ---

## build: Compile binary for current platform into run/
build:
	@mkdir -p $(RUNDIR)
	go build $(LDFLAGS) -o $(RUNDIR)/msngr ./cmd/msngr
	@test -f $(RUNDIR)/config.yaml || cp config.yaml.example $(RUNDIR)/config.yaml
	@echo "Built $(RUNDIR)/msngr"

DISTDIR  := dist
TARGETS  := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

## release: Cross-compile release binaries for all platforms into dist/
release:
	@rm -rf $(DISTDIR)
	@mkdir -p $(DISTDIR)
	@for target in $(TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		outdir="$(DISTDIR)/msngr-$(VERSION)-$${os}-$${arch}"; \
		mkdir -p "$$outdir"; \
		echo "Building $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o "$$outdir/msngr$${ext}" ./cmd/msngr || exit 1; \
		cp config.yaml.example "$$outdir/config.yaml.example"; \
		cp LICENSE "$$outdir/" 2>/dev/null || true; \
		cp README.md "$$outdir/"; \
		(cd $(DISTDIR) && tar czf "msngr-$(VERSION)-$${os}-$${arch}.tar.gz" "msngr-$(VERSION)-$${os}-$${arch}"); \
		rm -rf "$$outdir"; \
	done
	@cd $(DISTDIR) && shasum -a 256 *.tar.gz > checksums.txt
	@echo ""
	@echo "Release archives:"
	@ls -lh $(DISTDIR)/*.tar.gz
	@echo ""
	@cat $(DISTDIR)/checksums.txt

# --- Run ---

## run: Build and start the gateway
run: build
	cd $(RUNDIR) && ./msngr run

## init: Build and initialize the database
init: build
	cd $(RUNDIR) && ./msngr init

# --- Test ---

## test: Run tests with race detector
test:
	go test -race -count=1 ./...

## test-cover: Run tests with coverage report
test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	@rm -f coverage.out

# --- Lint ---

## lint: Run golangci-lint
lint:
	@which golangci-lint > /dev/null 2>&1 || { echo "Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	golangci-lint run ./...

## vet: Run go vet
vet:
	go vet ./...

## fmt: Format all Go source files
fmt:
	gofmt -l -w .

# --- Combined checks ---

## check: Run fmt + vet + test
check: fmt vet test
	@echo "All checks passed."

# --- Clean ---

## clean: Remove binary, database, storage, and dist/
clean:
	rm -rf $(RUNDIR)/msngr $(RUNDIR)/msngr.db $(RUNDIR)/msngr.db-shm $(RUNDIR)/msngr.db-wal
	rm -rf $(RUNDIR)/storage
	rm -rf $(DISTDIR)
