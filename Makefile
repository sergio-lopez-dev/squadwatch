GO      ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/go/bin/go)
BIN     := bin/squadwatch
PREFIX  ?= $(HOME)/.local

.PHONY: build install test vet run serve clean

build:
	$(GO) build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/squadwatch

install: build
	install -Dm755 $(BIN) $(PREFIX)/bin/squadwatch

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (echo "Ficheros sin formatear:"; gofmt -l .; exit 1)

run: build
	./$(BIN) scan

serve: build
	./$(BIN) serve

clean:
	$(GO) clean
	rm -f $(BIN)
