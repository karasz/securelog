package securelog

import (
	"os"
	"testing"
	"time"
)

func TestProtocol_Complete(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-protocol-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	logger, err := New(Config{AnchorEvery: 10}, store)
	if err != nil {
		t.Fatal(err)
	}

	logID := "test-log-001"

	// Initialize protocol
	commit, openMsg, err := logger.InitProtocol(logID)
	if err != nil {
		t.Fatal(err)
	}

	if commit.LogID != logID {
		t.Errorf("Expected LogID %s, got %s", logID, commit.LogID)
	}
	if openMsg.LogID != logID {
		t.Errorf("Expected LogID %s, got %s", logID, openMsg.LogID)
	}

	// Append some entries
	for i := 0; i < 5; i++ {
		_, err := logger.Append([]byte("test entry"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Close protocol
	closeMsg, err := logger.CloseProtocol(logID)
	if err != nil {
		t.Fatal(err)
	}

	if closeMsg.LogID != logID {
		t.Errorf("Expected LogID %s, got %s", logID, closeMsg.LogID)
	}

	// Verify with TrustedServer
	ts := NewTrustedServer()
	ts.RegisterLog(commit)
	ts.RegisterOpen(openMsg)
	err = ts.AcceptClosure(closeMsg)
	if err != nil {
		t.Fatalf("AcceptClosure failed: %v", err)
	}

	// Get all records
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	for r := range ch {
		records = append(records, r)
	}
	_ = done()

	// Final verification
	err = ts.FinalVerify(logID, records)
	if err != nil {
		t.Fatalf("FinalVerify failed: %v", err)
	}
}

func TestVerifyCloseMessage_Errors(t *testing.T) {
	// Test with empty records
	err := VerifyCloseMessage([]Record{}, CloseMessage{})
	if err == nil {
		t.Error("Expected error with empty records")
	}

	// Test with mismatched index
	records := []Record{
		{Index: 5, Msg: []byte("LOG_CLOSED")},
	}
	closeMsg := CloseMessage{FinalIndex: 10}

	err = VerifyCloseMessage(records, closeMsg)
	if err == nil {
		t.Error("Expected error with mismatched index")
	}

	// Test with wrong message
	records = []Record{
		{Index: 5, Msg: []byte("WRONG_MESSAGE")},
	}
	closeMsg = CloseMessage{FinalIndex: 5}

	err = VerifyCloseMessage(records, closeMsg)
	if err == nil {
		t.Error("Expected error with wrong closing message")
	}
}

func TestTrustedServer_AcceptClosure_UnknownLog(t *testing.T) {
	ts := NewTrustedServer()

	err := ts.AcceptClosure(CloseMessage{LogID: "unknown"})
	if err == nil {
		t.Error("Expected error accepting closure for unknown log")
	}
}

func TestTrustedServer_FinalVerify_Errors(t *testing.T) {
	ts := NewTrustedServer()

	// Test with unregistered log
	err := ts.FinalVerify("unknown", []Record{})
	if err == nil {
		t.Error("Expected error verifying unknown log")
	}

	// Test with no records
	ts.RegisterLog(InitCommitment{LogID: "test"})
	ts.RegisterOpen(OpenMessage{LogID: "test", FirstIndex: 1})
	err = ts.FinalVerify("test", []Record{})
	if err == nil {
		t.Error("Expected error with no records")
	}

	// Test without open message
	ts2 := NewTrustedServer()
	ts2.RegisterLog(InitCommitment{LogID: "test2"})
	err = ts2.FinalVerify("test2", []Record{{Index: 1}})
	if err == nil {
		t.Error("Expected error without open message")
	}

	// Test without closure - need a properly initialized log
	tmpDir, err := os.MkdirTemp("", "securelog-noclosure-*")
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

	commit, openMsg, err := logger.InitProtocol("test3")
	if err != nil {
		t.Fatal(err)
	}

	// Get the record
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	for r := range ch {
		records = append(records, r)
	}
	_ = done()

	ts3 := NewTrustedServer()
	ts3.RegisterLog(commit)
	ts3.RegisterOpen(openMsg)
	// Don't register closure - should fail with ErrLogNotClosed
	err = ts3.FinalVerify("test3", records)
	if err != ErrLogNotClosed {
		t.Errorf("Expected ErrLogNotClosed, got: %v", err)
	}
}

func TestDetectDelayedAttack(t *testing.T) {
	ts := NewTrustedServer()

	var tag1, tag2 [32]byte
	tag1[0] = 1
	tag2[0] = 2

	// Different tags - attack detected
	if !ts.DetectDelayedAttack("test", tag1, tag2) {
		t.Error("Should detect attack with different tags")
	}

	// Same tags - no attack
	if ts.DetectDelayedAttack("test", tag1, tag1) {
		t.Error("Should not detect attack with same tags")
	}
}
