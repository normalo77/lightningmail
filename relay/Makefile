# Relay-Core (Etappe 2a). Alles ueber dieses Makefile (PRECODING §D).
GO := $(shell command -v go 2>/dev/null || echo /usr/local/go/bin/go)
GOFMT := $(dir $(GO))gofmt

.PHONY: all build test vet fmt-check mod
all: fmt-check vet test build

build:
	$(GO) build ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt-check:
	@unformatted=$$($(GOFMT) -l .); \
	if [ -n "$$unformatted" ]; then echo "gofmt -l not empty:"; echo "$$unformatted"; exit 1; fi

mod:
	$(GO) mod tidy
