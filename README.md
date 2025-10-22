# securelog — Dual MAC Private-Verifiable Secure Logger (Go)

[![Go Reference](https://pkg.go.dev/badge/github.com/karasz/securelog.svg)](https://pkg.go.dev/github.com/karasz/securelog)
[![Go Report Card](https://goreportcard.com/badge/github.com/karasz/securelog)](https://goreportcard.com/report/github.com/karasz/securelog)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SecureLog is a production-focused implementation of the Dual MAC private-verifiable logging protocol. It keeps audit trails append-only, forward-secure, and verifiable by both semi-trusted auditors and a trusted authority. For the full academic background, see [doc/ACADEMICS.md](doc/ACADEMICS.md).

## Highlights
- Dual MAC chains (`μ_V`, `μ_T`) to catch tampering by compromised verifiers.
- Forward-secure key evolution with per-entry key rotation.
- Pluggable transports (folder, HTTP, local) and storage backends (POSIX files, SQLite).
- Pure Go, no CGO requirements in the default configuration.

## Quick Start

```go
package main

import (
	"log"
	"time"

	"github.com/karasz/securelog"
)

func main() {
	store, _ := securelog.OpenFileStore("/var/log/securelog")
	logger, _ := securelog.New(securelog.Config{AnchorEvery: 100}, store)

	commit, openMsg, _ := logger.InitProtocol("app-log-001")

	// transmit commit/openMsg to the trusted server here
	_ = commit
	_ = openMsg

	logger.Append([]byte("user login: alice"), time.Now())
	logger.Append([]byte("file access: /etc/passwd"), time.Now())

	closeMsg, _ := logger.CloseProtocol("app-log-001")
	log.Printf("final tag: %x", closeMsg.FinalTagT)
}
```

For end-to-end examples (including transports) check the `example_*.go` files.

## Storage Backends
- **File store (default)** — append-only binary format with POSIX locks; ideal for production.
- **SQLite store** — ACID semantics and ad-hoc queries via SQLite (`modernc.org/sqlite`).

Both implement the same `Store` interface, so swapping backends is a one-line change.

## Transports
- **Folder transport** for local/offline workflows.
- **HTTP transport** for remote trusted servers.
- **Local transport** for in-process testing.

Detailed diagrams and usage notes live in [doc/TRANSPORT.md](doc/TRANSPORT.md).

## Documentation
- [doc/ACADEMICS.md](doc/ACADEMICS.md) — paper references and detailed research context.
- [doc/TRANSPORT.md](doc/TRANSPORT.md) — transport layer protocol and folder layout.
- `example_*.go` — runnable snippets that stitch storage, transports, and verifiers together.

## Development

```
make fmt        # gofmt on the tree
make lint       # revive + staticcheck + gosec
make test       # go test -race -cover ./...
make check      # run the full battery (fmt, vet, lint, spell, test)
```

Go 1.21 or newer is recommended.
