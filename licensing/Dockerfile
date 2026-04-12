FROM golang:1.21-alpine AS builder
WORKDIR /app
RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build CLI tool
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o /usr/local/bin/ironwall-license \
    ./cmd/ironwall-license

# Build server
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -X main.version=1.0.0" \
    -o /usr/local/bin/license-server \
    ./cmd/license-server

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM alpine:3.19
RUN apk add --no-cache sqlite-libs ca-certificates tzdata curl

COPY --from=builder /usr/local/bin/ironwall-license /usr/local/bin/
COPY --from=builder /usr/local/bin/license-server   /usr/local/bin/

RUN addgroup -S ironwall && adduser -S ironwall -G ironwall
USER ironwall

WORKDIR /data
VOLUME ["/data"]

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:8090/api/v1/licensing/health || exit 1

CMD ["license-server"]
