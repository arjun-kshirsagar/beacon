.PHONY: build run test race vet fmt check fuzz

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
