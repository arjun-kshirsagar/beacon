.PHONY: build run test race vet fmt check

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
