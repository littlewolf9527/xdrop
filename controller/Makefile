.PHONY: all web build run clean deps test dev
BINARY=xdrop-controller
MAIN=./cmd/xdrop-controller
CONFIG?=$(CURDIR)/config.yaml

all: web
	$(MAKE) build

web:
	../scripts/build-controller.sh web

build:
	@test -s core/webui/build/index.html || (echo 'Run make web first'; exit 1)
	go build -tags webui -trimpath -o $(BINARY) $(MAIN)

run: build
	./$(BINARY) -config "$(CONFIG)"

clean:
	rm -f $(BINARY)

deps:
	go mod download
	cd ../console && npm ci

test:
	go test -v ./...

dev:
	@test -s core/webui/build/index.html || (echo 'Run make web first'; exit 1)
	go run -tags webui $(MAIN) -config "$(CONFIG)"
