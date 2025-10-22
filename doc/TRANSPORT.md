# Transport Layer: Communicating with Trusted Server T

This document explains how data is transported from the untrusted logger (U) to the trusted server (T) in the private-verifiable scheme.

## Overview

Per Section 4 of *A New Approach to Secure Logging*, the logger must coordinate three protocol phases with the trusted server:

1. **Log Initialization** – Deliver the initial commitment `(A₀, B₀)`, along with an opening message capturing the first entry and tags.
2. **Log Closure** – Notify T when the log closes, providing the final aggregate tags.
3. **Final Verification** – Supply the full log so T can validate the T-chain aggregates against its stored metadata.

Our implementation splits the initialization into two messages:

- `InitCommitment`: commits to key seeds and update policy.
- `OpenMessage`: confirms the `LOG_OPENED` entry, its index, and both aggregate tags.

```
┌─────────────┐                           ┌─────────────┐
│   Logger U  │                           │  Server T   │
│ (untrusted) │                           │  (trusted)  │
└─────────────┘                           └─────────────┘
       │                                         │
       │  1a. InitCommitment (A₀, B₀, meta)     │
       │────────────────────────────────────────>│
       │  1b. OpenMessage (LOG_OPENED tags)     │
       │────────────────────────────────────────>│
       │                                         │
       │  (U appends log entries…)               │
       │                                         │
       │  2. CloseMessage (μ_V,f, μ_T,f)         │
       │────────────────────────────────────────>│
       │                                         │
       │  3. Log file (records)                  │
       │────────────────────────────────────────>│
       │                                         │
       │  4. Verification result                 │
       │<────────────────────────────────────────│
```

## Transport Implementations

### Folder Transport (development/testing)

Stores metadata alongside logs on disk.

```
/shared/securelog/
  commitments/
    app-log-001.gob   # InitCommitment
  opens/
    app-log-001.gob   # OpenMessage
  closures/
    app-log-001.gob   # CloseMessage
  logs/
    app-log-001/
      logs.dat        # Entries
      anchors.idx     # Anchors
      tail.dat        # Tail state (μ_V, μ_T)
```

**Logger usage**
```go
transport, _ := securelog.NewFolderTransport("/shared/securelog")
logDir := "/shared/securelog/logs/app-log-001"
store, _ := securelog.OpenFileStore(logDir)

logger, _ := securelog.NewRemoteLogger(
    securelog.Config{AnchorEvery: 100},
    store,
    transport,
    "app-log-001",
)
```
`NewRemoteLogger` automatically:
1. Calls `InitProtocol`, which appends `LOG_OPENED` and returns `(InitCommitment, OpenMessage)`.
2. Sends both to T via `SendCommitment` and `SendOpen`.

Closing the logger sends the `CloseMessage`; `FolderTransport.VerifyLog` loads all three messages and checks the T-chain.

### HTTP Transport (production)

Endpoints expected by `Server`:
- `POST /api/v1/logs/register` – `InitCommitment`
- `POST /api/v1/logs/open` – `OpenMessage`
- `POST /api/v1/logs/close` – `CloseMessage`
- `POST /api/v1/logs/{id}/verify` – records for final verification

Example logger setup:
```go
store, _ := securelog.OpenFileStore("/var/log/myapp")
transport := securelog.NewHTTPTransport("https://trust.example.com")
logger, err := securelog.NewRemoteLogger(cfg, store, transport, "myapp-log-001")
```

### Local Transport (in-process)

For integration tests where U and T run in the same process:
```go
trusted := securelog.NewTrustedServer()
transport := securelog.NewLocalTransport(trusted, store)
logger, _ := securelog.NewRemoteLogger(cfg, store, transport, "test-log")
```
`SendCommitment`, `SendOpen`, and `SendClosure` map directly to `TrustedServer` methods.

### Custom Transport

Implement the interface:
```go
type Transport interface {
    SendCommitment(InitCommitment) error
    SendOpen(OpenMessage) error
    SendClosure(CloseMessage) error
    SendLogFile(logID string, records []Record) (bool, error)
}
```

## Security Notes

- **TLS with mutual auth:** ensure commitment/open/close messages are protected.
- **Key protection:** `(A₀, B₀)` and `OpenMessage` must be transmitted securely.
- **Delay-detection:** `OpenMessage` allows T to detect total deletion and verify the first entry’s tags.
- **Tail state:** the store writes only current aggregates (`tail.dat`, `tail` table); verifiers recompute from `LOG_OPENED` onward.

Ensure any new transport preserves the three-phase protocol: commitment, open, close, plus final verification.
