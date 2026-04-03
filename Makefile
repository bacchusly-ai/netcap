BINARY  = netcap
PLATFORMS = linux/amd64 linux/arm64 linux/loong64

.PHONY: build build-all test clean vet generate

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) ./cmd/netcap

build-all:
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%%/*} GOARCH=$${platform##*/} CGO_ENABLED=0 \
		go build -o bin/$(BINARY)-$${platform##*/} ./cmd/netcap; \
	done

test:
	go test ./...

clean:
	rm -rf bin/

vet:
	go vet ./...
