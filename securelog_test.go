package securelog

import (
	"crypto/hmac"
	"os"
	"path/filepath"
	"testing"
	"time"
)

//revive:disable:cyclomatic High complexity acceptable in tests
//revive:disable:cognitive-complexity High complexity acceptable in tests
//revive:disable:function-length Long test functions are acceptable

func TestFileStore_BasicOperations(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "securelog-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Open file store
	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatalf("OpenFileStore failed: %v", err)
	}
	defer store.(*fileStore).Close()

	// Create logger
	logger, err := New(Config{AnchorEvery: 10}, store)
	if err != nil {
		t.Fatalf("New logger failed: %v", err)
	}

	// Append some entries
	for i := 1; i <= 25; i++ {
		msg := []byte("test message")
		_, err := logger.Append(msg, time.Now())
		if err != nil {
			t.Fatalf("Append failed at %d: %v", i, err)
		}
	}

	// Verify anchors were created
	anchors, err := store.ListAnchors()
	if err != nil {
		t.Fatalf("ListAnchors failed: %v", err)
	}

	expectedAnchors := 2 // At index 10 and 20
	if len(anchors) != expectedAnchors {
		t.Fatalf("Expected %d anchors, got %d", expectedAnchors, len(anchors))
	}

	// Verify we can iterate records
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatalf("Iter failed: %v", err)
	}
	defer done()

	count := 0
	for range ch {
		count++
	}

	if count != 25 {
		t.Fatalf("Expected 25 records, got %d", count)
	}
}

func TestDualMACVerification(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	// Create logger
	logger, err := New(Config{AnchorEvery: 5}, store)
	if err != nil {
		t.Fatal(err)
	}

	// Get initial keys for trusted server
	a0, b0 := logger.GetInitialKeys()

	// Append entries
	for i := 1; i <= 10; i++ {
		_, err := logger.Append([]byte("entry"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Get records
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatal(err)
	}

	var records []Record
	for r := range ch {
		records = append(records, r)
	}
	_ = done()

	// Verify V-chain (semi-trusted verifier)
	var zeroTag [32]byte
	finalV, err := VerifyFrom(records, 0, a0, zeroTag)
	if err != nil {
		t.Fatalf("V-chain verification failed: %v", err)
	}
	tail, ok, err := store.Tail()
	if err != nil {
		t.Fatalf("Tail retrieval failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected tail state")
	}
	if !hmac.Equal(finalV[:], tail.TagV[:]) {
		t.Fatalf("V-chain final tag mismatch")
	}

	// Verify T-chain (trusted server)
	finalT, err := VerifyFromTrusted(records, 0, b0, zeroTag)
	if err != nil {
		t.Fatalf("T-chain verification failed: %v", err)
	}
	if !hmac.Equal(finalT[:], tail.TagT[:]) {
		t.Fatalf("T-chain final tag mismatch")
	}
}

func TestProtocol(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	logger, err := New(Config{AnchorEvery: 5}, store)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize protocol
	trustedServer := NewTrustedServer()
	commit, openMsg, err := logger.InitProtocol("test-log-001")
	if err != nil {
		t.Fatal(err)
	}
	trustedServer.RegisterLog(commit)
	trustedServer.RegisterOpen(openMsg)

	// Append entries
	for i := 1; i <= 10; i++ {
		_, err := logger.Append([]byte("entry"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Close log
	closeMsg, err := logger.CloseProtocol("test-log-001")
	if err != nil {
		t.Fatalf("CloseProtocol failed: %v", err)
	}

	err = trustedServer.AcceptClosure(closeMsg)
	if err != nil {
		t.Fatalf("AcceptClosure failed: %v", err)
	}

	// Get records
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatal(err)
	}

	var records []Record
	for r := range ch {
		records = append(records, r)
	}
	_ = done()

	// Final verification by trusted server
	err = trustedServer.FinalVerify("test-log-001", records)
	if err != nil {
		t.Fatalf("FinalVerify failed: %v", err)
	}
}

func TestSQLiteStore_BasicOperations(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := OpenSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteStore failed: %v", err)
	}

	logger, err := New(Config{AnchorEvery: 5}, store)
	if err != nil {
		t.Fatal(err)
	}

	// Append entries
	for i := 1; i <= 10; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Verify anchors
	anchors, err := store.ListAnchors()
	if err != nil {
		t.Fatal(err)
	}

	if len(anchors) != 2 {
		t.Fatalf("Expected 2 anchors, got %d", len(anchors))
	}
}

func TestTampering_Detection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	logger, err := New(Config{}, store)
	if err != nil {
		t.Fatal(err)
	}

	a0, b0 := logger.GetInitialKeys()

	// Append entries
	for i := 1; i <= 5; i++ {
		_, err := logger.Append([]byte("entry"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Get records
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatal(err)
	}

	var records []Record
	for r := range ch {
		records = append(records, r)
	}
	_ = done()

	// First verify that unmodified records pass verification
	var zeroTag [32]byte
	_, err = VerifyFrom(records, 0, a0, zeroTag)
	if err != nil {
		t.Fatalf("VerifyFrom failed on valid records: %v", err)
	}

	_, err = VerifyFromTrusted(records, 0, b0, zeroTag)
	if err != nil {
		t.Fatalf("VerifyFromTrusted failed on valid records: %v", err)
	}

	// Now tamper with a record message (but not its tags)
	records[2].Msg = []byte("TAMPERED")

	// Verification should now FAIL because the stored tag won't match the tampered message
	_, err = VerifyFrom(records, 0, a0, zeroTag)
	if err == nil {
		t.Fatal("Expected VerifyFrom to fail with tampered data, but it passed")
	}
	if err != ErrTagMismatch {
		t.Fatalf("Expected ErrTagMismatch, got: %v", err)
	}

	_, err = VerifyFromTrusted(records, 0, b0, zeroTag)
	if err == nil {
		t.Fatal("Expected VerifyFromTrusted to fail with tampered data, but it passed")
	}
	if err != ErrTagMismatch {
		t.Fatalf("Expected ErrTagMismatch, got: %v", err)
	}
}

func TestFolderTransport(t *testing.T) {
	// Create temporary directory for shared folder
	tmpDir, err := os.MkdirTemp("", "securelog-folder-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// === Logger U Side ===

	// Create folder transport
	transport, err := NewFolderTransport(tmpDir)
	if err != nil {
		t.Fatalf("NewFolderTransport failed: %v", err)
	}

	// Create logger with file storage in shared logs directory
	logID := "test-app-001"
	logDir := filepath.Join(tmpDir, "logs", logID)
	store, err := OpenFileStore(logDir)
	if err != nil {
		t.Fatalf("OpenFileStore failed: %v", err)
	}
	defer store.(*fileStore).Close()

	// Create remote logger (auto-sends commitment)
	logger, err := NewRemoteLogger(
		Config{AnchorEvery: 10},
		store,
		transport,
		logID,
	)
	if err != nil {
		t.Fatalf("NewRemoteLogger failed: %v", err)
	}

	// Append some entries
	for i := 1; i <= 25; i++ {
		_, err := logger.Append([]byte("test event"), time.Now())
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Close log (auto-sends closure)
	err = logger.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// === Trusted Server T Side ===

	// Create another transport instance (simulating T reading from folder)
	tTransport, err := NewFolderTransport(tmpDir)
	if err != nil {
		t.Fatalf("NewFolderTransport for T failed: %v", err)
	}

	// Verify commitment exists
	commit, err := tTransport.LoadCommitment(logID)
	if err != nil {
		t.Fatalf("LoadCommitment failed: %v", err)
	}
	if commit.LogID != logID {
		t.Fatalf("Expected logID %s, got %s", logID, commit.LogID)
	}

	// Verify closure exists
	closure, err := tTransport.LoadClosure(logID)
	if err != nil {
		t.Fatalf("LoadClosure failed: %v", err)
	}
	if closure.LogID != logID {
		t.Fatalf("Expected logID %s, got %s", logID, closure.LogID)
	}

	// Verify the log using T-chain
	err = tTransport.VerifyLog(logID)
	if err != nil {
		t.Fatalf("VerifyLog failed: %v", err)
	}

	// Test that we can read the log store
	tStore, err := tTransport.GetLogStore(logID)
	if err != nil {
		t.Fatalf("GetLogStore failed: %v", err)
	}
	defer tStore.(*fileStore).Close()

	ch, done, err := tStore.Iter(1)
	if err != nil {
		t.Fatalf("Iter failed: %v", err)
	}
	var count int
	for range ch {
		count++
	}
	_ = done()

	expectedCount := 27 // LOG_OPENED + 25 regular entries + 1 closing entry
	if count != expectedCount {
		t.Fatalf("Expected %d records, got %d", expectedCount, count)
	}
}
