# ---- Build stage ----
FROM golang:1.22-bookworm AS builder

# github.com/mattn/go-sqlite3 uses cgo, so we need a C compiler here.
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go.mod/go.sum first so dependency downloads are cached across builds
COPY go.mod go.sum* ./
RUN go mod download

# Copy the rest of the source and build the binary (cgo required for sqlite3)
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /build/cli-login-system ./cmd

# ---- Runtime stage ----
FROM debian:bookworm-slim

# ca-certificates in case we ever need TLS calls. The sqlite3 C library
# itself is compiled directly into our binary via cgo (go-sqlite3 bundles
# the amalgamation source), so no separate libsqlite3 package is needed
# at runtime — only glibc, which this base image already provides.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/cli-login-system /app/cli-login-system
# Note: no need to copy internal/db/migrations here — the schema SQL is
# embedded directly into the binary at compile time via go:embed.

# SQLite database file will live in this mounted volume so data
# survives container restarts.
VOLUME ["/data"]
ENV DB_PATH=/data/app.db

ENTRYPOINT ["/app/cli-login-system"]
