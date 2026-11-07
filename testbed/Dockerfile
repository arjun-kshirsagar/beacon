# Builds beacon and the attack-lab tools into one small image. Built from the
# repository root: docker compose -f testbed/docker-compose.yml build
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/beacon ./cmd/beacon && \
    CGO_ENABLED=0 go build -o /out/attacker ./cmd/attacker

FROM alpine:3.22
RUN apk add --no-cache coreutils
COPY --from=build /out/beacon /out/attacker /usr/local/bin/
# The attack tools refuse to run without this; only testbed containers set it.
ENV BEACON_TESTBED=1
WORKDIR /lab
CMD ["sleep", "infinity"]
