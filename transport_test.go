package securelog

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

//revive:disable:cyclomatic High complexity acceptable in tests
//revive:disable:cognitive-complexity High complexity acceptable in tests
//revive:disable:function-length Long test functions are acceptable

func TestNewHTTPTransport(t *testing.T) {
	transport := NewHTTPTransport("https://example.com")
	if transport == nil {
		t.Fatal("NewHTTPTransport returned nil")
	}
	if transport.BaseURL != "https://example.com" {
		t.Errorf("Expected BaseURL 'https://example.com', got %s", transport.BaseURL)
	}
	if transport.Client == nil {
		t.Error("HTTP client should not be nil")
	}
}

func TestHTTPTransport_SendCommitment(t *testing.T) {
	// Create a test server
	srv := NewServer()
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Create transport
	transport := NewHTTPTransport(ts.URL)

	// Send commitment
	commit := InitCommitment{
		LogID: "test-http",
		KeyA0: [KeySize]byte{1, 2, 3},
		KeyB0: [KeySize]byte{4, 5, 6},
	}

	err := transport.SendCommitment(commit)
	if err != nil {
		t.Fatalf("SendCommitment failed: %v", err)
	}

	// Verify commitment was registered
	if _, ok := srv.TrustedServer.commitments[commit.LogID]; !ok {
		t.Error("Commitment was not registered")
	}
}

func TestHTTPTransport_SendOpen(t *testing.T) {
	srv := NewServer()
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	transport := NewHTTPTransport(ts.URL)

	// Register log first
	commit := InitCommitment{
		LogID: "test-http",
		KeyA0: [KeySize]byte{1, 2, 3},
		KeyB0: [KeySize]byte{4, 5, 6},
	}
	srv.TrustedServer.RegisterLog(commit)

	// Send open message
	openMsg := OpenMessage{
		LogID:      "test-http",
		FirstIndex: 1,
		FirstTagV:  [32]byte{7, 8, 9},
		FirstTagT:  [32]byte{10, 11, 12},
	}

	err := transport.SendOpen(openMsg)
	if err != nil {
		t.Fatalf("SendOpen failed: %v", err)
	}

	// Verify open was registered
	if _, ok := srv.TrustedServer.opens[openMsg.LogID]; !ok {
		t.Error("Open message was not registered")
	}
}

func TestHTTPTransport_SendClosure(t *testing.T) {
	srv := NewServer()
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	transport := NewHTTPTransport(ts.URL)

	// Register log first
	commit := InitCommitment{
		LogID: "test-http",
		KeyA0: [KeySize]byte{1, 2, 3},
		KeyB0: [KeySize]byte{4, 5, 6},
	}
	srv.TrustedServer.RegisterLog(commit)

	// Send closure
	closeMsg := CloseMessage{
		LogID:      "test-http",
		FinalIndex: 10,
		FinalTagV:  [32]byte{13, 14, 15},
		FinalTagT:  [32]byte{16, 17, 18},
	}

	err := transport.SendClosure(closeMsg)
	if err != nil {
		t.Fatalf("SendClosure failed: %v", err)
	}

	// Verify closure was registered
	if _, ok := srv.TrustedServer.closures[closeMsg.LogID]; !ok {
		t.Error("Closure was not registered")
	}
}

func TestHTTPTransport_SendLogFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-http-*")
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

	logID := "test-http"
	commit, openMsg, err := logger.InitProtocol(logID)
	if err != nil {
		t.Fatal(err)
	}

	// Append entries
	for i := 0; i < 3; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	closeMsg, err := logger.CloseProtocol(logID)
	if err != nil {
		t.Fatal(err)
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

	// Setup server
	srv := NewServer()
	srv.TrustedServer.RegisterLog(commit)
	srv.TrustedServer.RegisterOpen(openMsg)
	_ = srv.TrustedServer.AcceptClosure(closeMsg)

	mux := http.NewServeMux()
	srv.SetupRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Send log file
	transport := NewHTTPTransport(ts.URL)
	verified, err := transport.SendLogFile(logID, records)
	if err != nil {
		t.Fatalf("SendLogFile failed: %v", err)
	}
	if !verified {
		t.Error("Expected verification to pass")
	}
}

func TestHTTPTransport_ServerError(t *testing.T) {
	// Create a server that returns errors
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	transport := NewHTTPTransport(ts.URL)

	commit := InitCommitment{
		LogID: "test",
		KeyA0: [KeySize]byte{1, 2, 3},
		KeyB0: [KeySize]byte{4, 5, 6},
	}

	err := transport.SendCommitment(commit)
	if err == nil {
		t.Error("Expected error when server returns 500")
	}
}

func TestLocalTransport(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-local-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	ts := NewTrustedServer()
	transport := NewLocalTransport(ts, store)

	logger, err := New(Config{}, store)
	if err != nil {
		t.Fatal(err)
	}

	logID := "test-local"
	commit, openMsg, err := logger.InitProtocol(logID)
	if err != nil {
		t.Fatal(err)
	}

	// Send commitment
	err = transport.SendCommitment(commit)
	if err != nil {
		t.Fatalf("SendCommitment failed: %v", err)
	}

	// Send open
	err = transport.SendOpen(openMsg)
	if err != nil {
		t.Fatalf("SendOpen failed: %v", err)
	}

	// Append entries
	for i := 0; i < 3; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Close
	closeMsg, err := logger.CloseProtocol(logID)
	if err != nil {
		t.Fatal(err)
	}

	err = transport.SendClosure(closeMsg)
	if err != nil {
		t.Fatalf("SendClosure failed: %v", err)
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

	// Verify
	verified, err := transport.SendLogFile(logID, records)
	if err != nil {
		t.Fatalf("SendLogFile failed: %v", err)
	}
	if !verified {
		t.Error("Expected verification to pass")
	}
}

func TestFolderTransport_Complete(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-folder-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	transport, err := NewFolderTransport(tmpDir)
	if err != nil {
		t.Fatalf("NewFolderTransport failed: %v", err)
	}

	// Verify directory structure was created
	for _, subdir := range []string{"commitments", "opens", "closures", "logs"} {
		dir := filepath.Join(tmpDir, subdir)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Directory %s was not created", subdir)
		}
	}

	// Create a log in the logs subdirectory
	logID := "test-folder"
	logDir := filepath.Join(tmpDir, "logs", logID)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		t.Fatal(err)
	}

	store, err := OpenFileStore(logDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	logger, err := New(Config{}, store)
	if err != nil {
		t.Fatal(err)
	}

	commit, openMsg, err := logger.InitProtocol(logID)
	if err != nil {
		t.Fatal(err)
	}

	// Send commitment
	err = transport.SendCommitment(commit)
	if err != nil {
		t.Fatalf("SendCommitment failed: %v", err)
	}

	// Verify commitment file exists
	commitPath := filepath.Join(tmpDir, "commitments", logID+".gob")
	if _, err := os.Stat(commitPath); os.IsNotExist(err) {
		t.Error("Commitment file was not created")
	}

	// Load commitment back
	loadedCommit, err := transport.LoadCommitment(logID)
	if err != nil {
		t.Fatalf("LoadCommitment failed: %v", err)
	}
	if loadedCommit.LogID != commit.LogID {
		t.Errorf("Expected LogID %s, got %s", commit.LogID, loadedCommit.LogID)
	}

	// Send open
	err = transport.SendOpen(openMsg)
	if err != nil {
		t.Fatalf("SendOpen failed: %v", err)
	}

	// Load open back
	loadedOpen, err := transport.LoadOpen(logID)
	if err != nil {
		t.Fatalf("LoadOpen failed: %v", err)
	}
	if loadedOpen.LogID != openMsg.LogID {
		t.Errorf("Expected LogID %s, got %s", openMsg.LogID, loadedOpen.LogID)
	}

	// Append entries
	for i := 0; i < 3; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Close
	closeMsg, err := logger.CloseProtocol(logID)
	if err != nil {
		t.Fatal(err)
	}

	err = transport.SendClosure(closeMsg)
	if err != nil {
		t.Fatalf("SendClosure failed: %v", err)
	}

	// Load closure back
	loadedClose, err := transport.LoadClosure(logID)
	if err != nil {
		t.Fatalf("LoadClosure failed: %v", err)
	}
	if loadedClose.LogID != closeMsg.LogID {
		t.Errorf("Expected LogID %s, got %s", closeMsg.LogID, loadedClose.LogID)
	}

	// Verify log
	err = transport.VerifyLog(logID)
	if err != nil {
		t.Fatalf("VerifyLog failed: %v", err)
	}

	// Test GetLogStore
	logStore, err := transport.GetLogStore(logID)
	if err != nil {
		t.Fatalf("GetLogStore failed: %v", err)
	}
	if logStore == nil {
		t.Error("GetLogStore returned nil")
	}
}

func TestFolderTransport_SendLogFileExistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-folder-sendlog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	transport, err := NewFolderTransport(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	logID := "test-log"
	logDir := filepath.Join(tmpDir, "logs", logID)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		t.Fatal(err)
	}

	store, err := OpenFileStore(logDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	logger, err := New(Config{}, store)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = logger.InitProtocol(logID)
	if err != nil {
		t.Fatal(err)
	}

	// SendLogFile should verify log exists
	verified, err := transport.SendLogFile(logID, nil)
	if err != nil {
		t.Fatalf("SendLogFile failed: %v", err)
	}
	if !verified {
		t.Error("Expected verification to pass")
	}

	// Test with non-existent log
	_, err = transport.SendLogFile("nonexistent", nil)
	if err == nil {
		t.Error("Expected error for non-existent log")
	}
}

func TestFolderTransport_LoadErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-folder-errors-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	transport, err := NewFolderTransport(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// Test loading non-existent files
	_, err = transport.LoadCommitment("nonexistent")
	if err == nil {
		t.Error("Expected error loading non-existent commitment")
	}

	_, err = transport.LoadOpen("nonexistent")
	if err == nil {
		t.Error("Expected error loading non-existent open message")
	}

	_, err = transport.LoadClosure("nonexistent")
	if err == nil {
		t.Error("Expected error loading non-existent closure")
	}

	// Test verifying non-existent log
	err = transport.VerifyLog("nonexistent")
	if err == nil {
		t.Error("Expected error verifying non-existent log")
	}
}

func TestRemoteLogger(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-remote-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	ts := NewTrustedServer()
	transport := NewLocalTransport(ts, store)

	// Create remote logger
	logID := "test-remote"
	remoteLogger, err := NewRemoteLogger(Config{}, store, transport, logID)
	if err != nil {
		t.Fatalf("NewRemoteLogger failed: %v", err)
	}

	// Verify commitment and open were sent automatically
	if _, ok := ts.commitments[logID]; !ok {
		t.Error("Commitment was not sent automatically")
	}
	if _, ok := ts.opens[logID]; !ok {
		t.Error("Open message was not sent automatically")
	}

	// Append entries
	for i := 0; i < 3; i++ {
		_, err := remoteLogger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Close
	err = remoteLogger.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify closure was sent
	if _, ok := ts.closures[logID]; !ok {
		t.Error("Closure was not sent")
	}
}

func TestHmacEqual(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{1, 2, 3, 5}
	d := []byte{1, 2, 3}

	if !hmacEqual(a, b) {
		t.Error("Equal slices should return true")
	}

	if hmacEqual(a, c) {
		t.Error("Different slices should return false")
	}

	if hmacEqual(a, d) {
		t.Error("Different length slices should return false")
	}
}
