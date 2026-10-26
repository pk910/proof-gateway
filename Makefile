# proof-gateway
VERSION := $(shell git rev-parse --short HEAD)
BUILDTIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GOLDFLAGS += -X 'main.BuildVersion="$(VERSION)"'
GOLDFLAGS += -X 'main.BuildTime="$(BUILDTIME)"'
GOLDFLAGS += -X 'main.BuildRelease="$(RELEASE)"'

.PHONY: all test build docker clean

all: test build

test:
	go test -race ./...

build:
	@echo version: $(VERSION)
	env CGO_ENABLED=0 go build -v -trimpath -o bin/ -ldflags="-s -w $(GOLDFLAGS)" .

docker:
	docker build . -t pk910/proof-gateway:dev

clean:
	rm -f bin/*
