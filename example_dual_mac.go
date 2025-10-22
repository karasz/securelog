// Package securelog implements a forward-secure logging system with dual MAC chains.
package securelog

// Example: Dual MAC Secure Logging System
//
// This example demonstrates the complete dual MAC chain implementation
// as described in "A New Approach to Secure Logging" (Section 4).
//
// Security Properties:
// 1. Forward Security: Compromise of current keys doesn't allow forging past entries
// 2. Truncation Attack Prevention: Both MAC chains prevent tail deletion
// 3. Delayed Detection Attack Prevention: T-chain protects against malicious verifiers
// 4. Total Deletion Attack Prevention: Initial commitment to trusted server
//
// Usage:
//   // 1. Logger U creates log and registers with trusted server T
//   logger, _ := New(Config{AnchorEvery: 100}, store)
//   trustedServer := NewTrustedServer()
//   commit, openMsg, _ := logger.InitProtocol("app-log-001")
//   trustedServer.RegisterLog(commit)
//   trustedServer.RegisterOpen(openMsg)
//
//   // 2. Logger appends entries (both μ_V and μ_T computed)
//   logger.Append([]byte("user login"), time.Now())
//   logger.Append([]byte("file access"), time.Now())
//
//   // 3. Semi-trusted verifier V can verify using V-chain
//   verifier := NewSemiTrustedVerifier(store)
//   verifier.VerifyFromAnchor(anchor)  // Uses A_i and μ_V,i
//
//   // 4. When log is closed, trusted server T performs final verification
//   closeMsg, _ := logger.CloseProtocol("app-log-001")
//   trustedServer.AcceptClosure(closeMsg)
//   trustedServer.FinalVerify("app-log-001", records)  // Uses B_0 and μ_T,f
//
// Attack Scenarios:
//
// Scenario 1: Malicious Verifier V tries to modify logs
//   - V has A_i and can verify V-chain
//   - V modifies some log entries
//   - V recomputes μ_V,i' to make verification pass for other verifiers
//   - BUT: V cannot forge μ_T,i because V doesn't have B_i
//   - Result: Trusted server T detects tampering when it verifies T-chain
//
// Scenario 2: Attacker compromises logger U at time b
//   - Attacker gets A_b and B_b
//   - Can forge entries from time b onward
//   - CANNOT forge entries before time b (forward security)
//   - CANNOT delete entries without detection (both chains break)
//
// Scenario 3: Delayed Detection Attack (prevented by dual MAC)
//   - Without dual MAC: V could modify pre-compromise records before T sees them
//   - With dual MAC: V's modifications break T-chain, detected when T verifies
//
