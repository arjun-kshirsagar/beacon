.PHONY: build run test race vet fmt check fuzz snapshot

build:
	go build -o bin/beacon ./cmd/beacon

run:
	go run ./cmd/beacon $(ARGS)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

check: vet race

# Run every fuzz target; override the per-target time with FUZZTIME=10m.
fuzz:
	./scripts/fuzz.sh

# Build release archives into dist/ without publishing (see docs/RELEASING.md).
snapshot:
	go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean
