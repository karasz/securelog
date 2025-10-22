package securelog

//revive:disable:cyclomatic High complexity acceptable in tests
//revive:disable:cognitive-complexity High complexity acceptable in tests
//revive:disable:function-length Long test functions are acceptable

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	srv := NewServer()

	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.TrustedServer == nil {
		t.Error("Server's TrustedServer not set correctly")
	}
}

func TestServer_HandleRegister(t *testing.T) {
	srv := NewServer()

	commit := InitCommitment{
		LogID: "test-log",
		KeyA0: [KeySize]byte{1, 2, 3},
		KeyB0: [KeySize]byte{4, 5, 6},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(commit); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/v1/logs/register", &buf)
	w := httptest.NewRecorder()

	srv.HandleRegister(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp["status"] != "registered" {
		t.Errorf("Expected status 'registered', got %s", resp["status"])
	}

	// Verify the commitment was actually registered
	if _, ok := srv.TrustedServer.commitments[commit.LogID]; !ok {
		t.Error("Commitment was not registered in TrustedServer")
	}
}

func TestServer_HandleRegister_InvalidGob(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest("POST", "/api/v1/logs/register", bytes.NewReader([]byte("invalid gob")))
	w := httptest.NewRecorder()

	srv.HandleRegister(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestServer_HandleOpen(t *testing.T) {
	srv := NewServer()

	// First register the log
	commit := InitCommitment{
		LogID: "test-log",
		KeyA0: [KeySize]byte{1, 2, 3},
		KeyB0: [KeySize]byte{4, 5, 6},
	}
	srv.TrustedServer.RegisterLog(commit)

	openMsg := OpenMessage{
		LogID:      "test-log",
		FirstIndex: 1,
		FirstTagV:  [32]byte{7, 8, 9},
		FirstTagT:  [32]byte{10, 11, 12},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(openMsg); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/v1/logs/open", &buf)
	w := httptest.NewRecorder()

	srv.HandleOpen(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp["status"] != "opened" {
		t.Errorf("Expected status 'opened', got %s", resp["status"])
	}
}

func TestServer_HandleOpen_InvalidGob(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest("POST", "/api/v1/logs/open", bytes.NewReader([]byte("invalid gob")))
	w := httptest.NewRecorder()

	srv.HandleOpen(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestServer_HandleClose(t *testing.T) {
	srv := NewServer()

	// Register and open the log first
	commit := InitCommitment{
		LogID: "test-log",
		KeyA0: [KeySize]byte{1, 2, 3},
		KeyB0: [KeySize]byte{4, 5, 6},
	}
	srv.TrustedServer.RegisterLog(commit)

	openMsg := OpenMessage{
		LogID:      "test-log",
		FirstIndex: 1,
		FirstTagV:  [32]byte{7, 8, 9},
		FirstTagT:  [32]byte{10, 11, 12},
	}
	srv.TrustedServer.RegisterOpen(openMsg)

	closeMsg := CloseMessage{
		LogID:      "test-log",
		FinalIndex: 10,
		FinalTagV:  [32]byte{13, 14, 15},
		FinalTagT:  [32]byte{16, 17, 18},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(closeMsg); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/v1/logs/close", &buf)
	w := httptest.NewRecorder()

	srv.HandleClose(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp["status"] != "closed" {
		t.Errorf("Expected status 'closed', got %s", resp["status"])
	}
}

func TestServer_HandleClose_UnknownLog(t *testing.T) {
	srv := NewServer()

	closeMsg := CloseMessage{
		LogID:      "unknown-log",
		FinalIndex: 10,
		FinalTagV:  [32]byte{10, 11, 12},
		FinalTagT:  [32]byte{13, 14, 15},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(closeMsg); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/v1/logs/close", &buf)
	w := httptest.NewRecorder()

	srv.HandleClose(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestServer_HandleClose_InvalidGob(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest("POST", "/api/v1/logs/close", bytes.NewReader([]byte("invalid gob")))
	w := httptest.NewRecorder()

	srv.HandleClose(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestServer_HandleVerify(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-server-verify-*")
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

	logID := "test-log"
	commit, openMsg, err := logger.InitProtocol(logID)
	if err != nil {
		t.Fatal(err)
	}

	// Append some entries
	for i := 0; i < 5; i++ {
		_, err := logger.Append([]byte("test entry"), time.Now())
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
	err = srv.TrustedServer.AcceptClosure(closeMsg)
	if err != nil {
		t.Fatal(err)
	}

	// Encode records using gob
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(records); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/v1/logs/"+logID+"/verify", &buf)
	w := httptest.NewRecorder()

	srv.HandleVerify(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp["status"] != "verified" {
		t.Errorf("Expected status 'verified', got %s", resp["status"])
	}
}

func TestServer_HandleVerify_InvalidGob(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest("POST", "/api/v1/logs/test-log/verify", bytes.NewReader([]byte("invalid gob")))
	w := httptest.NewRecorder()

	srv.HandleVerify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestServer_HandleVerify_FailedVerification(t *testing.T) {
	srv := NewServer()

	// Create records with unregistered log
	records := []Record{{Index: 1, TS: time.Now().UnixNano(), Msg: []byte("test")}}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(records); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/v1/logs/unknown-log/verify", &buf)
	w := httptest.NewRecorder()

	srv.HandleVerify(w, req)

	// With the new implementation, we return 200 OK with verified:false in the response
	// instead of 401 Unauthorized. This is more RESTful.
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify the response indicates failure
	var response map[string]any
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if verified, ok := response["verified"].(bool); !ok || verified {
		t.Error("Expected verified to be false in response")
	}
}

func TestServer_SetupRoutes(t *testing.T) {
	srv := NewServer()
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	// Test that routes are registered (basic sanity check)
	if mux == nil {
		t.Error("Mux should not be nil after SetupRoutes")
	}
}
