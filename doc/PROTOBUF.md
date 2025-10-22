# Protocol Buffer Implementation

This document describes the Protocol Buffer (protobuf) implementation for SecureLog's communication with the trusted server.

## Overview

Protocol Buffers provide an efficient, language-agnostic binary serialization format for communicating with the trusted server. This is more efficient than Gob and more flexible than JSON.

## Benefits

### 1. **Efficiency**
- **Compact binary format**: 2-10x smaller than JSON
- **Fast encoding/decoding**: ~250ns per record on modern hardware
- **Low memory overhead**: 400 bytes/op for encoding, 352 bytes/op for decoding

### 2. **Language Agnostic**
- Clients can be written in any language (Python, Java, Rust, JavaScript, etc.)
- Official protobuf support for 20+ languages
- Makes it easy to build monitoring tools, dashboards, and integrations

### 3. **Schema Evolution**
- Add new fields without breaking old clients
- Remove fields while maintaining compatibility
- Version your protocol safely

### 4. **Type Safety**
- Strongly typed schema prevents data corruption
- Validation happens at decode time
- Binary format prevents injection attacks

## Size Comparison

For a single `Record` with a 100-byte message:

| Format   | Size    | Notes                      |
|----------|---------|----------------------------|
| Gob      | ~180 B  | Go-only                    |
| Protobuf | ~175 B  | Language-agnostic          |
| JSON     | ~231 B  | Human-readable, 31% larger |

For 1000 records:

| Format   | Size     | Overhead |
|----------|----------|----------|
| Gob      | ~180 KB  | 0%       |
| Protobuf | ~175 KB  | -3%      |
| JSON     | ~231 KB  | +28%     |

## Performance

Based on benchmarks on AMD Ryzen 7 PRO 6850U:

```
BenchmarkProtoEncoding/Encode        4,727,722 ops    253.9 ns/op    400 B/op    3 allocs/op
BenchmarkProtoEncoding/Decode        3,814,921 ops    310.5 ns/op    352 B/op    5 allocs/op
BenchmarkProtoBatchEncoding/Encode      59,696 ops   20.7 μs/op   38.5 KB/op  203 allocs/op
```

For 100 records, encoding takes ~20 microseconds - fast enough for real-time logging.

## API Endpoints

### Protocol Buffer Endpoints

All protobuf endpoints use `Content-Type: application/x-protobuf`.

#### 1. Register Log
```
POST /api/v1/logs/register
Body: InitCommitment (protobuf)
```

#### 2. Open Log
```
POST /api/v1/logs/open
Body: OpenMessage (protobuf)
```

#### 3. Close Log
```
POST /api/v1/logs/close
Body: CloseMessage (protobuf)
```

#### 4. Verify Log
```
POST /api/v1/logs/{logID}/verify
Body: VerifyRequest (protobuf)
Response: VerifyResponse (protobuf)
```

## Usage

### Go Client

```go
import (
    "github.com/karasz/securelog"
)

// Create Protocol Buffer HTTP transport
transport := securelog.NewProtoHTTPTransport("https://trust.example.com")

// Create remote logger
logID := "my-application-log"
cfg := securelog.Config{AnchorEvery: 100}
store := securelog.NewMemStore()

logger, err := securelog.NewRemoteLogger(cfg, store, transport, logID)
if err != nil {
    log.Fatal(err)
}

// Log entries
logger.Append([]byte("User logged in"), time.Now())
logger.Append([]byte("File accessed"), time.Now())

// Close log
logger.Close()
```

### Python Client (Example)

```python
import requests
from proto import securelog_pb2

# Create commitment
commit = securelog_pb2.InitCommitment()
commit.log_id = "python-log"
commit.start_time.GetCurrentTime()
commit.key_a0 = os.urandom(32)
commit.key_b0 = os.urandom(32)
commit.update_freq = 1000

# Send to server
response = requests.post(
    "https://trust.example.com/api/v1/logs/register",
    data=commit.SerializeToString(),
    headers={"Content-Type": "application/x-protobuf"}
)
```

### JavaScript Client (Example)

```javascript
const protobuf = require('protobufjs');

// Load schema
const root = await protobuf.load('securelog.proto');
const InitCommitment = root.lookupType('securelog.InitCommitment');

// Create message
const commit = InitCommitment.create({
    logId: "js-log",
    startTime: { seconds: Date.now() / 1000 },
    keyA0: crypto.randomBytes(32),
    keyB0: crypto.randomBytes(32),
    updateFreq: 1000
});

// Encode
const buffer = InitCommitment.encode(commit).finish();

// Send
await fetch('https://trust.example.com/api/v1/logs/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-protobuf' },
    body: buffer
});
```

## Schema Definition

The protobuf schema is defined in [proto/securelog.proto](../proto/securelog.proto):

```protobuf
message InitCommitment {
  string log_id = 1;
  google.protobuf.Timestamp start_time = 2;
  bytes key_a0 = 3;        // 32 bytes
  bytes key_b0 = 4;        // 32 bytes
  uint64 update_freq = 5;
}

message Record {
  uint64 index = 1;
  int64 ts = 2;
  bytes msg = 3;
  bytes tag_v = 4;  // 32 bytes
  bytes tag_t = 5;  // 32 bytes
}
```

## Regenerating Go Code

If you modify the `.proto` file:

```bash
# Install protoc-gen-go
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

# Regenerate Go code
protoc --go_out=. --go_opt=paths=source_relative proto/securelog.proto
```

## Testing

Run the protobuf tests:

```bash
# All protobuf tests
go test -v -run "Proto"

# Benchmarks
go test -bench=BenchmarkProto -benchmem
```

## Security Considerations

1. **Transport Security**: Always use HTTPS in production to prevent man-in-the-middle attacks
2. **Binary Validation**: The 32-byte tag fields are validated at decode time
3. **Size Limits**: Consider adding max message size limits to prevent DoS attacks
4. **Authentication**: Add API keys or mutual TLS for trusted server authentication

## Backward Compatibility

Protocol Buffers support schema evolution:

- **Adding fields**: Old clients ignore new fields
- **Removing fields**: Mark as deprecated, remove after migration period
- **Changing types**: Use new field numbers instead
- **Renaming fields**: Only the field number matters, not the name

Example safe evolution:

```protobuf
message Record {
  uint64 index = 1;
  int64 ts = 2;
  bytes msg = 3;
  bytes tag_v = 4;
  bytes tag_t = 5;
  // New optional field - safe to add
  string source_ip = 6;
}
```

## Comparison with Alternatives

| Feature              | Gob   | Protobuf | JSON | MessagePack |
|---------------------|-------|----------|------|-------------|
| Size                | Good  | Best     | Poor | Good        |
| Speed               | Fast  | Fastest  | Slow | Fast        |
| Language Support    | Go    | All      | All  | Most        |
| Human Readable      | No    | No       | Yes  | No          |
| Schema Evolution    | No    | Yes      | No   | Limited     |
| Type Safety         | Yes   | Yes      | No   | Limited     |

## Implementation Files

- [proto/securelog.proto](../proto/securelog.proto) - Protocol Buffer schema
- [proto/securelog.pb.go](../proto/securelog.pb.go) - Generated Go code
- [proto_convert.go](../proto_convert.go) - Conversion between Go structs and protobuf
- [proto_transport.go](../proto_transport.go) - HTTP transport implementation
- [proto_convert_test.go](../proto_convert_test.go) - Conversion tests
- [proto_transport_test.go](../proto_transport_test.go) - Transport tests
- [example_protobuf.go](../example_protobuf.go) - Usage examples

## Future Enhancements

Potential improvements:

1. **gRPC Support**: Add gRPC service definitions for streaming
2. **Compression**: Add optional gzip compression for large batches
3. **Batching**: Implement automatic batching of log entries
4. **Streaming**: Use bidirectional streaming for real-time verification
