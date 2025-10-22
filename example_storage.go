package securelog

// Storage Backend Comparison
//
// This package provides two storage backends for secure logging:
//
// 1. POSIX File Storage (file_store.go) - DEFAULT & RECOMMENDED
//    - Simple append-only binary files
//    - File locking for concurrency
//    - Zero external dependencies (stdlib only)
//    - Best for: production use, embedded systems, minimal dependencies
//
// 2. SQLite Storage (sqlite_store.go) - ALTERNATIVE
//    - Uses SQLite database with WAL mode
//    - ACID transactions
//    - SQL queries for flexible access
//    - Best for: applications already using SQLite, complex queries
//
// Usage Examples:
//
// === POSIX File Storage (Default, Recommended) ===
//
//   import "securelog"
//
//   // Open file store (recommended for production)
//   store, err := securelog.OpenFileStore("/var/log/secure")
//   if err != nil {
//       log.Fatal(err)
//   }
//
//   // Create logger
//   logger, _ := securelog.New(securelog.Config{AnchorEvery: 100}, store)
//   logger.Append([]byte("event 1"), time.Now())
//
//
// === SQLite Storage (Alternative) ===
//
//   import "securelog"
//
//   // Open SQLite store
//   store, err := securelog.OpenSQLiteStore("file:app.db")
//   if err != nil {
//       log.Fatal(err)
//   }
//
//   // Create logger (same API!)
//   logger, _ := securelog.New(securelog.Config{AnchorEvery: 100}, store)
//   logger.Append([]byte("event 1"), time.Now())
//
//
// File Format (POSIX storage):
//
//   logs.dat format:
//   ┌──────────────────────────────────────────────┐
//   │ Entry 1                                      │
//   ├──────────────────────────────────────────────┤
//   │ [8 bytes] index (uint64 big-endian)          │
//   │ [8 bytes] timestamp (int64 big-endian)       │
//   │ [4 bytes] message length (uint32 big-endian) │
//   │ [n bytes] message data                       │
//   │ [32 bytes] tagV (μ_V,i)                      │
//   │ [32 bytes] tagT (μ_T,i)                      │
//   ├──────────────────────────────────────────────┤
//   │ Entry 2                                      │
//   │ ...                                          │
//   └──────────────────────────────────────────────┘
//
//   anchors.idx format:
//   ┌──────────────────────────────────────────────┐
//   │ Anchor 1                                     │
//   ├──────────────────────────────────────────────┤
//   │ [8 bytes] index (uint64 big-endian)          │
//   │ [32 bytes] key (A_i)                         │
//   │ [32 bytes] tagV (μ_V,i)                      │
//   │ [32 bytes] tagT (μ_T,i)                      │
//   ├──────────────────────────────────────────────┤
//   │ Anchor 2                                     │
//   │ ...                                          │
//   └──────────────────────────────────────────────┘
//
//
// Performance Characteristics:
//
// POSIX File Storage (Recommended):
//   ✓ No dependencies (pure Go + POSIX) - BEST FOR PRODUCTION
//   ✓ Simple, auditable binary format
//   ✓ Lower memory footprint (~1-5 MB)
//   ✓ Minimal attack surface (no SQL parser)
//   - Sequential scan for iteration
//   - File locking overhead
//
// SQLite Storage (Alternative):
//   ✓ Transactions ensure atomicity
//   ✓ Indexed queries for fast lookups
//   ✓ WAL mode for concurrent reads
//   - Requires SQLite library dependency
//   - Higher memory usage (~10-50 MB)
//
//
// Migration Between Backends:
//
//   // Export from SQLite
//   sqlStore, _ := securelog.OpenSQLiteStore("app.db")
//   ch, done, _ := sqlStore.Iter(1)
//   var records []securelog.Record
//   for r := range ch {
//       records = append(records, r)
//   }
//   done()
//
//   // Import to file storage
//   fileStore, _ := securelog.OpenFileStore("/var/log/secure")
//   for _, r := range records {
//       tail := securelog.TailState{Index: r.Index, TagV: r.TagV, TagT: r.TagT}
//       fileStore.Append(r, tail, nil) // Anchors handled separately
//   }
//
