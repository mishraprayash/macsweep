GO       ?= go
BINARY   := sweep
PKG      := ./cmd/sweep
VERSION  ?= dev
LDFLAGS  := -s -w -X main.version=$(VERSION)

.PHONY: all build test race vet lint cover bench demo release install clean

all: vet lint test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(PKG)

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./internal/scanner/

# Runs sweep on a generated fixture tree in a temp sandbox with HOME redirected.
demo: build
	./scripts/sandbox-demo.sh

# Release archives for GitHub: one per architecture plus a universal binary,
# each with the README and LICENSE, and SHA256SUMS. Archive names carry no
# version, so install.sh can always fetch releases/latest/download/<name>.
release: clean
	@mkdir -p dist/stage
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/stage/arm64/$(BINARY) $(PKG)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/stage/amd64/$(BINARY) $(PKG)
	@mkdir -p dist/stage/universal
	lipo -create -output dist/stage/universal/$(BINARY) dist/stage/arm64/$(BINARY) dist/stage/amd64/$(BINARY)
	for a in arm64 amd64 universal; do \
		cp README.md LICENSE dist/stage/$$a/ && \
		tar -czf dist/$(BINARY)-darwin-$$a.tar.gz -C dist/stage/$$a $(BINARY) README.md LICENSE || exit 1; \
	done
	rm -rf dist/stage
	cd dist && shasum -a 256 $(BINARY)-*.tar.gz > SHA256SUMS

# Copies the binary to PREFIX/bin (default /usr/local/bin). Run it yourself.
PREFIX ?= /usr/local
install: build
	install -m 0755 bin/$(BINARY) $(PREFIX)/bin/$(BINARY)

clean:
	rm -rf bin dist coverage.out
