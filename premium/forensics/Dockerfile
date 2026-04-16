FROM golang:1.21-alpine AS builder
RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -X main.version=1.0.0 -X main.publisher=OPTIMIUM_NEXUS_LLC" \
    -o /usr/local/bin/axelus-forensics \
    ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache libpcap ca-certificates tzdata curl

COPY --from=builder /usr/local/bin/axelus-forensics /usr/local/bin/

RUN addgroup -S axelus && adduser -S axelus -G axelus
RUN mkdir -p /data/forensics && chown axelus:axelus /data/forensics

USER axelus
WORKDIR /data/forensics
VOLUME ["/data/forensics"]

EXPOSE 8095

HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8095/health || exit 1

CMD ["axelus-forensics"]
