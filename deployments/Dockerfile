# Stage 1: Build
FROM golang:1.22 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /netcap ./cmd/netcap

# Stage 2: Runtime
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates ethtool iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /netcap /usr/local/bin/netcap
COPY scripts/tune-nic.sh /usr/local/bin/tune-nic.sh

ENTRYPOINT ["/usr/local/bin/netcap"]
