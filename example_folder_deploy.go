package securelog

// Example: Folder-based Self-Contained Deployment
//
// This example shows how to use FolderTransport for a self-contained deployment
// where the trusted server T is represented by a local folder structure.
//
// Use case: Development, testing, or single-machine deployments without network requirements.
//
// Folder Structure:
//   /shared/securelog/
//     commitments/
//       app-log-001.gob    - Initial commitment from logger U
//     closures/
//       app-log-001.gob    - Closure message from logger U
//     logs/
//       app-log-001/
//         logs.dat         - Binary log entries
//         anchors.idx      - Anchor entries
//
// Security Note: This is "non-secure" in that U and T share the same filesystem.
// In production, U and T should be on separate machines with secure transport.
//
// Usage Example:
//
//   // ===== On Logger U side =====
//
//   // Create shared folder transport
//   transport, _ := securelog.NewFolderTransport("/shared/securelog")
//
//   // Create logger with file storage in the shared logs directory
//   logDir := "/shared/securelog/logs/app-log-001"
//   store, _ := securelog.OpenFileStore(logDir)
//
//   // Create remote logger (auto-sends commitment)
//   logger, _ := securelog.NewRemoteLogger(
//       securelog.Config{AnchorEvery: 100},
//       store,
//       transport,
//       "app-log-001",
//   )
//
//   // Use logger normally
//   logger.Append([]byte("user login: alice"), time.Now())
//   logger.Append([]byte("file access: /etc/passwd"), time.Now())
//
//   // Close log (auto-sends closure)
//   logger.Close()
//
//
//   // ===== On Trusted Server T side =====
//
//   // Open the same folder transport
//   transport, _ := securelog.NewFolderTransport("/shared/securelog")
//
//   // Verify the log using T-chain
//   err := transport.VerifyLog("app-log-001")
//   if err != nil {
//       log.Fatal("T-chain verification failed:", err)
//   }
//   fmt.Println("Log verified successfully by T!")
//
//
// Migration to Network Deployment:
//
// When ready for production, simply replace FolderTransport with HTTPTransport:
//
//   // Before (folder-based):
//   transport, _ := securelog.NewFolderTransport("/shared/securelog")
//
//   // After (network-based):
//   transport := securelog.NewHTTPTransport("https://trust.example.com")
//
// The rest of the code remains unchanged!
//
//
// Advantages of Folder-based Deployment:
//   ✓ No network configuration needed
//   ✓ Easy to test and debug
//   ✓ Simple backup (just copy the folder)
//   ✓ Works offline
//   ✓ Perfect for development and testing
//
// Limitations:
//   - U and T share filesystem (not truly separated)
//   - No network isolation between U and T
//   - Only suitable for single-machine deployments
//   - Should NOT be used in production where U might be compromised
