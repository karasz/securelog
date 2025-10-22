package securelog

import (
	"bytes"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/karasz/securelog/proto"
	"google.golang.org/protobuf/proto"
)

func TestServer_HandleRegister_Protobuf(t *testing.T) {
	server := NewServer()

	var keyA0, keyB0 [KeySize]byte
	for i := range keyA0 {
		keyA0[i] = byte(i)
		keyB0[i] = byte(i + 100)
	}

	commit := InitCommitment{
		LogID:      "test-log-proto",
		StartTime:  time.Now(),
		KeyA0:      keyA0,
		KeyB0:      keyB0,
		UpdateFreq: 1000,
	}

	// Convert to protobuf
	pbCommit := ToProtoInitCommitment(commit)
	data, err := proto.Marshal(pbCommit)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logs/register", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/x-protobuf")

	w := httptest.NewRecorder()
	server.HandleRegister(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the commitment was registered
	if _, ok := server.TrustedServer.commitments[commit.LogID]; !ok {
		t.Error("Commitment was not registered")
	}
}

func TestServer_HandleOpen_Protobuf(t *testing.T) {
	server := NewServer()

	// First register the log
	var keyA0, keyB0 [KeySize]byte
	commit := InitCommitment{
		LogID:      "test-log-open",
		StartTime:  time.Now(),
		KeyA0:      keyA0,
		KeyB0:      keyB0,
		UpdateFreq: 1000,
	}
	server.TrustedServer.RegisterLog(commit)

	var tagV, tagT [32]byte
	for i := range tagV {
		tagV[i] = byte(i)
		tagT[i] = byte(i + 50)
	}

	open := OpenMessage{
		LogID:      "test-log-open",
		OpenTime:   time.Now(),
		FirstIndex: 1,
		FirstTagV:  tagV,
		FirstTagT:  tagT,
	}

	// Convert to protobuf
	pbOpen := ToProtoOpenMessage(open)
	data, err := proto.Marshal(pbOpen)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logs/open", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/x-protobuf")

	w := httptest.NewRecorder()
	server.HandleOpen(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the open message was registered
	if _, ok := server.TrustedServer.opens[open.LogID]; !ok {
		t.Error("Open message was not registered")
	}
}

func TestServer_HandleClose_Protobuf(t *testing.T) {
	server := NewServer()

	// First register the log
	var keyA0, keyB0 [KeySize]byte
	commit := InitCommitment{
		LogID:      "test-log-close",
		StartTime:  time.Now(),
		KeyA0:      keyA0,
		KeyB0:      keyB0,
		UpdateFreq: 1000,
	}
	server.TrustedServer.RegisterLog(commit)

	var tagV, tagT [32]byte
	closeMsg := CloseMessage{
		LogID:      "test-log-close",
		CloseTime:  time.Now(),
		FinalIndex: 100,
		FinalTagV:  tagV,
		FinalTagT:  tagT,
	}

	// Convert to protobuf
	pbClose := ToProtoCloseMessage(closeMsg)
	data, err := proto.Marshal(pbClose)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logs/close", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/x-protobuf")

	w := httptest.NewRecorder()
	server.HandleClose(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the closure was registered
	if _, ok := server.TrustedServer.closures[closeMsg.LogID]; !ok {
		t.Error("Closure was not registered")
	}
}

func TestServer_HandleVerify_Protobuf(t *testing.T) {
	server := NewServer()

	// Setup: Create a log with proper initialization
	var keyA0, keyB0 [KeySize]byte
	for i := range keyA0 {
		keyA0[i] = byte(i)
		keyB0[i] = byte(i + 100)
	}

	logID := "test-verify-proto"
	commit := InitCommitment{
		LogID:      logID,
		StartTime:  time.Now(),
		KeyA0:      keyA0,
		KeyB0:      keyB0,
		UpdateFreq: 1,
	}
	server.TrustedServer.RegisterLog(commit)

	// Create a logger to generate valid records
	tmpDir := t.TempDir()
	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	logger, err := New(Config{InitialKeyV: &keyA0, InitialKeyT: &keyB0}, store)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Generate some records
	_, openMsg, err := logger.InitProtocol(logID)
	if err != nil {
		t.Fatalf("Failed to init protocol: %v", err)
	}
	server.TrustedServer.RegisterOpen(openMsg)

	_, err = logger.Append([]byte("test entry"), time.Now())
	if err != nil {
		t.Fatalf("Failed to append: %v", err)
	}

	closeMsg, err := logger.CloseProtocol(logID)
	if err != nil {
		t.Fatalf("Failed to close: %v", err)
	}
	_ = server.TrustedServer.AcceptClosure(closeMsg)

	// Get all records
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatalf("Failed to iterate: %v", err)
	}

	var records []Record
	for rec := range ch {
		records = append(records, rec)
	}
	_ = done()

	// Create protobuf verify request
	req := &pb.VerifyRequest{
		LogId:   logID,
		Records: ToProtoRecords(records),
	}
	data, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal verify request: %v", err)
	}

	// Send request
	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/logs/"+logID+"/verify", bytes.NewReader(data))
	httpReq.Header.Set("Content-Type", "application/x-protobuf")

	w := httptest.NewRecorder()
	server.HandleVerify(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Decode protobuf response
	var resp pb.VerifyResponse
	if err := proto.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !resp.Verified {
		t.Errorf("Expected verified=true, got false: %s", resp.ErrorMessage)
	}
}

func TestServer_HandleVerify_Protobuf_Failed(t *testing.T) {
	server := NewServer()

	// Setup with invalid data (no commitment)
	logID := "test-verify-fail"

	var tagV, tagT [32]byte
	records := []Record{
		{
			Index: 1,
			TS:    time.Now().UnixNano(),
			Msg:   []byte("test"),
			TagV:  tagV,
			TagT:  tagT,
		},
	}

	// Create protobuf verify request
	req := &pb.VerifyRequest{
		LogId:   logID,
		Records: ToProtoRecords(records),
	}
	data, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal verify request: %v", err)
	}

	// Send request
	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/logs/"+logID+"/verify", bytes.NewReader(data))
	httpReq.Header.Set("Content-Type", "application/x-protobuf")

	w := httptest.NewRecorder()
	server.HandleVerify(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Decode protobuf response
	var resp pb.VerifyResponse
	if err := proto.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if resp.Verified {
		t.Error("Expected verified=false, got true")
	}
	if resp.ErrorMessage == "" {
		t.Error("Expected error message, got empty string")
	}
}

func TestServer_MixedProtocols(t *testing.T) {
	// Test that server can handle both Gob and Protobuf in the same session
	server := NewServer()

	var keyA0, keyB0 [KeySize]byte
	for i := range keyA0 {
		keyA0[i] = byte(i)
		keyB0[i] = byte(i + 100)
	}

	// Send commitment via Protobuf
	commitProto := InitCommitment{
		LogID:      "mixed-proto",
		StartTime:  time.Now(),
		KeyA0:      keyA0,
		KeyB0:      keyB0,
		UpdateFreq: 1000,
	}
	pbCommit := ToProtoInitCommitment(commitProto)
	dataProto, _ := proto.Marshal(pbCommit)

	reqProto := httptest.NewRequest(http.MethodPost, "/api/v1/logs/register", bytes.NewReader(dataProto))
	reqProto.Header.Set("Content-Type", "application/x-protobuf")

	wProto := httptest.NewRecorder()
	server.HandleRegister(wProto, reqProto)

	if wProto.Code != http.StatusOK {
		t.Errorf("Protobuf request failed: %d", wProto.Code)
	}

	// Send commitment via Gob
	commitGob := InitCommitment{
		LogID:      "mixed-gob",
		StartTime:  time.Now(),
		KeyA0:      keyA0,
		KeyB0:      keyB0,
		UpdateFreq: 1000,
	}
	var bufGob bytes.Buffer
	_ = gob.NewEncoder(&bufGob).Encode(commitGob)

	reqGob := httptest.NewRequest(http.MethodPost, "/api/v1/logs/register", &bufGob)
	reqGob.Header.Set("Content-Type", "application/octet-stream")

	wGob := httptest.NewRecorder()
	server.HandleRegister(wGob, reqGob)

	if wGob.Code != http.StatusOK {
		t.Errorf("Gob request failed: %d", wGob.Code)
	}

	// Verify both were registered
	if _, ok := server.TrustedServer.commitments["mixed-proto"]; !ok {
		t.Error("Protobuf commitment not registered")
	}
	if _, ok := server.TrustedServer.commitments["mixed-gob"]; !ok {
		t.Error("Gob commitment not registered")
	}
}
