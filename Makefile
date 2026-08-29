# Makefile for netwhy (Zero-Dependency Hackathon, Track C: Web & Network)

BINARY_NAME=netwhy
CMD_PATH=.
DIST_DIR=dist

.PHONY: all build test vet race proof repro clean

all: build test vet

build:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o $(DIST_DIR)/$(BINARY_NAME) $(CMD_PATH)

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race ./...

proof:
	@echo "=== Active Module List ==="
	go list -m all
	@echo "=== Module Graph ==="
	go mod graph

repro:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o $(DIST_DIR)/build-a $(CMD_PATH)
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o $(DIST_DIR)/build-b $(CMD_PATH)
	@sha256sum $(DIST_DIR)/build-a $(DIST_DIR)/build-b 2>/dev/null || sha256 $(DIST_DIR)/build-a $(DIST_DIR)/build-b 2>/dev/null || echo "Builds completed in $(DIST_DIR)/"

clean:
	rm -rf $(DIST_DIR)
