GO      ?= go
LDFLAGS := -s -w
BUILD   := CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)"
CMDS    := krot-server krot-client krot-keygen krotctl

.PHONY: all test vet keygen clean linux-amd64 linux-arm64 dist

## Build all binaries for the host platform into ./bin
all:
	@mkdir -p bin
	@for c in $(CMDS); do $(BUILD) -o bin/$$c ./cmd/$$c; done
	@echo "built: $(CMDS) -> ./bin"

## Run the test suite (transport handshake + framing round trip)
test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

## Generate a fresh PSK + server identity + config templates
keygen:
	@$(GO) run ./cmd/krot-keygen

## Cross-compile static Linux binaries
linux-amd64:
	@mkdir -p dist/linux-amd64
	@for c in $(CMDS); do GOOS=linux GOARCH=amd64 $(BUILD) -o dist/linux-amd64/$$c ./cmd/$$c; done
	@echo "-> dist/linux-amd64"

linux-arm64:
	@mkdir -p dist/linux-arm64
	@for c in $(CMDS); do GOOS=linux GOARCH=arm64 $(BUILD) -o dist/linux-arm64/$$c ./cmd/$$c; done
	@echo "-> dist/linux-arm64"

dist: linux-amd64 linux-arm64

clean:
	rm -rf bin dist
