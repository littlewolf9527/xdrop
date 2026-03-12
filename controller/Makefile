.PHONY: all build run clean

BINARY=xdrop-controller
MAIN=./cmd/controller

all: build

build:
	@echo "[INFO] Building Controller..."
	go build -o $(BINARY) $(MAIN)
	@echo "[INFO] Build complete: $(BINARY)"

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)

deps:
	go mod tidy

test:
	go test -v ./...

# Run in development mode
dev:
	go run $(MAIN)
