package securelog

// Example: Protocol Buffer Transport for Secure Logging
//
// This example demonstrates using Protocol Buffers for communication between
// the logger (U) and the trusted server (T).
//
// Why Protocol Buffers?
// 1. Language-agnostic: Trusted server T can be written in any language
// 2. Compact binary format: More efficient than JSON
// 3. Schema evolution: Backward/forward compatible updates
// 4. Fast encoding/decoding: Better performance than text formats
//
// Use case: Production deployments where the trusted server is a separate
// service, potentially written in a different language (Java, Python, Rust, etc.)
//
// Architecture:
//
//   ┌─────────────────┐                        ┌─────────────────┐
//   │   Logger U      │                        │ Trusted Server T│
//   │   (Go)          │                        │  (Any Language) │
//   ├─────────────────┤                        ├─────────────────┤
//   │ RemoteLogger    │                        │ REST API        │
//   │                 │   HTTP + Protobuf      │                 │
//   │ ProtoTransport  ├───────────────────────>│ /api/init       │
//   │                 │                        │ /api/open       │
//   │ FileStore       │                        │ /api/close      │
//   │ /var/log/app/   │                        │ /api/verify     │
//   └─────────────────┘                        └─────────────────┘
//
// Protocol Messages (defined in proto/securelog.proto):
//
// 1. InitCommitment - Initial commitment from logger to server
//    - log_id: Unique identifier for the log
//    - start_time: When logging begins
//    - key_a0: Initial key for V-chain (A_0)
//    - key_b0: Initial key for T-chain (B_0)
//    - update_freq: Anchor interval
//
// 2. OpenMessage - First record notification
//    - log_id: Log identifier
//    - open_time: When first record was written
//    - first_index: Index of first entry (usually 2)
//    - first_tag_v: μ_V,1 for V-chain
//    - first_tag_t: μ_T,1 for T-chain
//
// 3. CloseMessage - Log closure notification
//    - log_id: Log identifier
//    - close_time: When log was closed
//    - final_index: Index of last entry
//    - final_tag_v: μ_V,f for V-chain
//    - final_tag_t: μ_T,f for T-chain
//
// 4. Record - Individual log entry
//    - index: Sequence number
//    - ts: Timestamp (protobuf.Timestamp)
//    - msg: Log message bytes
//    - tag_v: μ_V,i for V-chain
//    - tag_t: μ_T,i for T-chain
//
// 5. VerifyRequest - Batch verification request
//    - log_id: Log identifier
//    - records: Array of Record messages
//
// 6. VerifyResponse - Verification result
//    - verified: Boolean result
//    - error_message: Description if verification fails
//
//
// Usage Example:
//
//   // ===== Logger U (Go) =====
//
//   import (
//       "securelog"
//       "time"
//   )
//
//   // Create Protocol Buffer transport
//   transport := securelog.NewProtoHTTPTransport("https://trust.example.com")
//
//   // Create file store for local log storage
//   store, _ := securelog.OpenFileStore("/var/log/myapp")
//
//   // Create remote logger (sends InitCommitment via protobuf)
//   logger, _ := securelog.NewRemoteLogger(
//       securelog.Config{AnchorEvery: 100},
//       store,
//       transport,
//       "app-log-001",
//   )
//
//   // Append entries
//   logger.Append([]byte("user login: alice"), time.Now())
//   logger.Append([]byte("file access: /etc/passwd"), time.Now())
//
//   // Close log (sends CloseMessage via protobuf)
//   logger.Close()
//
//
//   // ===== Trusted Server T (Python example) =====
//
//   from flask import Flask, request
//   from proto import securelog_pb2
//
//   app = Flask(__name__)
//   trusted_server = TrustedServer()
//
//   @app.route('/api/init', methods=['POST'])
//   def handle_init():
//       # Decode protobuf message
//       commit = securelog_pb2.InitCommitment()
//       commit.ParseFromString(request.data)
//
//       # Store commitment
//       trusted_server.register_log(
//           commit.log_id,
//           commit.key_a0,
//           commit.key_b0,
//           commit.start_time
//       )
//       return b"OK"
//
//   @app.route('/api/close', methods=['POST'])
//   def handle_close():
//       # Decode protobuf message
//       close = securelog_pb2.CloseMessage()
//       close.ParseFromString(request.data)
//
//       # Accept closure
//       trusted_server.accept_closure(
//           close.log_id,
//           close.final_index,
//           close.final_tag_t
//       )
//       return b"OK"
//
//   @app.route('/api/verify', methods=['POST'])
//   def handle_verify():
//       # Decode protobuf message
//       req = securelog_pb2.VerifyRequest()
//       req.ParseFromString(request.data)
//
//       # Verify T-chain
//       verified = trusted_server.verify_records(
//           req.log_id,
//           req.records
//       )
//
//       # Return protobuf response
//       resp = securelog_pb2.VerifyResponse()
//       resp.verified = verified
//       return resp.SerializeToString()
//
//
// Size Comparison (1000 log entries with 100-byte messages):
//
//   Format      Size       Notes
//   ─────────────────────────────────────────────────────────
//   Gob         ~180 KB    Go-only, not portable
//   Protobuf    ~175 KB    Language-agnostic, portable
//   JSON        ~231 KB    31% larger, human-readable
//
//
// Performance Benefits:
//
//   ✓ Cross-language compatibility (Go logger + Python/Java/Rust server)
//   ✓ Compact binary format (~24% smaller than JSON)
//   ✓ Fast serialization/deserialization (2-10x faster than JSON)
//   ✓ Strong typing with schema validation
//   ✓ Forward/backward compatibility for protocol evolution
//   ✓ Built-in timestamp handling (google.protobuf.Timestamp)
//
//
// Security Considerations:
//
// 1. TLS Required: Always use HTTPS for protobuf transport
//    - Prevents man-in-the-middle attacks
//    - Protects keys during transmission
//
// 2. Authentication: Implement auth tokens or mutual TLS
//    - Verify logger identity before accepting commits
//    - Prevent unauthorized log registration
//
// 3. Rate Limiting: Protect trusted server from DoS
//    - Limit requests per log ID
//    - Cap maximum record batch size
//
// 4. Input Validation: Parse protobuf messages carefully
//    - Check log_id format and length
//    - Validate timestamp ranges
//    - Verify tag lengths (must be 32 bytes)
//
//
// Deployment Example (Docker Compose):
//
//   version: '3.8'
//   services:
//     logger:
//       image: myapp:latest
//       environment:
//         - SECURELOG_TRANSPORT=proto
//         - SECURELOG_SERVER=https://trusted-server:8443
//       volumes:
//         - /var/log/myapp:/logs
//
//     trusted-server:
//       image: trusted-server:latest
//       ports:
//         - "8443:8443"
//       volumes:
//         - /var/securelog:/data
//       environment:
//         - TLS_CERT=/certs/server.crt
//         - TLS_KEY=/certs/server.key
//
//
// Generating Protobuf Code for Other Languages:
//
//   # Python
//   protoc --python_out=. proto/securelog.proto
//
//   # Java
//   protoc --java_out=. proto/securelog.proto
//
//   # Rust
//   protoc --rust_out=. proto/securelog.proto
//
//   # C++
//   protoc --cpp_out=. proto/securelog.proto
//
//   # C#
//   protoc --csharp_out=. proto/securelog.proto
//
//
// Migration from Gob to Protobuf:
//
// If you're currently using the default Gob transport and want to migrate:
//
//   // Before (Gob-based):
//   transport := securelog.NewHTTPTransport("https://trust.example.com")
//
//   // After (Protobuf-based):
//   transport := securelog.NewProtoHTTPTransport("https://trust.example.com")
//
// The rest of your logger code remains unchanged!
//
//
// Wire Format Example:
//
// InitCommitment message (hexdump):
//   0a 0c 61 70 70 2d 6c 6f  67 2d 30 30 31 12 0b 08  |..app-log-001...|
//   ef c7 cb 93 06 10 00 1a  20 a1 b2 c3 d4 e5 f6 a1  |........ .......|
//   b2 c3 d4 e5 f6 a1 b2 c3  d4 e5 f6 a1 b2 c3 d4 e5  |................|
//   [32 bytes for key_a0, 32 bytes for key_b0...]
//
//
// Advantages over Gob Transport:
//
//   Gob Transport (Default):
//   ✓ No protobuf dependency
//   ✓ Slightly simpler setup
//   ✓ Good for Go-only deployments
//   - Cannot interop with non-Go servers
//   - Gob format not standardized
//
//   Protobuf Transport (This Example):
//   ✓ Language-agnostic (Go, Python, Java, Rust, etc.)
//   ✓ Industry-standard format
//   ✓ Better documentation and tooling
//   ✓ More compact than JSON
//   - Requires protoc compiler
//   - Extra dependency (google.golang.org/protobuf)
//
