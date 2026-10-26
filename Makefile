VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
GOEXE := $(shell go env GOEXE)

.PHONY: build test vet fmt snapshot clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o vpnsplit$(GOEXE) ./cmd/vpnsplit

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# builds every OS/arch exactly like a release, without publishing (needs goreleaser)
snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf vpnsplit vpnsplit.exe dist
