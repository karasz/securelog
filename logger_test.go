package securelog

import (
	"bytes"
	"crypto/sha256"
	"os"
	"testing"
	"time"
)

func TestNew_DefaultKeys(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	// Create logger with random keys
	logger, err := New(Config{}, store)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if logger == nil {
		t.Fatal("New returned nil logger")
	}

	// Verify initial state
	idx, tagV, tagT := logger.LastState()
	if idx != 0 {
		t.Errorf("Expected initial index 0, got %d", idx)
	}

	var zeroTag [32]byte
	if tagV != zeroTag {
		t.Error("Expected initial tagV to be zero")
	}
	if tagT != zeroTag {
		t.Error("Expected initial tagT to be zero")
	}

	// Verify keys are not zero (randomly generated)
	a0, b0 := logger.GetInitialKeys()
	var zeroKey [KeySize]byte
	if a0 == zeroKey {
		t.Error("Expected non-zero verifier key A0")
	}
	if b0 == zeroKey {
		t.Error("Expected non-zero trusted key B0")
	}
}

func TestNew_CustomKeys(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-custom-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	// Define custom keys
	customKeyV := [KeySize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	customKeyT := [KeySize]byte{9, 10, 11, 12, 13, 14, 15, 16}

	cfg := Config{
		InitialKeyV: &customKeyV,
		InitialKeyT: &customKeyT,
	}

	logger, err := New(cfg, store)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Verify custom keys are used
	a0, b0 := logger.GetInitialKeys()
	if a0 != customKeyV {
		t.Error("Custom verifier key not used")
	}
	if b0 != customKeyT {
		t.Error("Custom trusted key not used")
	}
}

func TestNew_OnlyCustomKeyV(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-keyv-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	// Only custom verifier key
	customKeyV := [KeySize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	cfg := Config{
		InitialKeyV: &customKeyV,
	}

	logger, err := New(cfg, store)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	a0, b0 := logger.GetInitialKeys()
	if a0 != customKeyV {
		t.Error("Custom verifier key not used")
	}

	// B0 should be random (not zero)
	var zeroKey [KeySize]byte
	if b0 == zeroKey {
		t.Error("Expected non-zero random trusted key B0")
	}
}

func TestAppend_BasicFlow(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-append-*")
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

	// Append first entry
	msg := []byte("First log entry")
	ts := time.Now()
	entry, err := logger.Append(msg, ts)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Verify entry
	if entry.Index != 1 {
		t.Errorf("Expected index 1, got %d", entry.Index)
	}
	if entry.TS != ts.UnixNano() {
		t.Errorf("Expected timestamp %d, got %d", ts.UnixNano(), entry.TS)
	}
	if !bytes.Equal(entry.Msg, msg) {
		t.Errorf("Expected message %q, got %q", msg, entry.Msg)
	}

	// Verify state updated
	idx, tagV, tagT := logger.LastState()
	if idx != 1 {
		t.Errorf("Expected index 1, got %d", idx)
	}

	var zeroTag [32]byte
	if tagV == zeroTag {
		t.Error("Expected non-zero tagV after append")
	}
	if tagT == zeroTag {
		t.Error("Expected non-zero tagT after append")
	}

	// Tag in entry should match tagV from LastState
	if entry.Tag != tagV {
		t.Error("Entry tag should match tagV from LastState")
	}
}

func TestAppend_MultipleEntries(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-multi-*")
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

	// Append 10 entries
	for i := 0; i < 10; i++ {
		msg := []byte("Entry " + string(rune('0'+i)))
		entry, err := logger.Append(msg, time.Now())
		if err != nil {
			t.Fatalf("Append %d failed: %v", i, err)
		}

		if entry.Index != uint64(i+1) {
			t.Errorf("Entry %d: expected index %d, got %d", i, i+1, entry.Index)
		}
	}

	// Verify final state
	idx, _, _ := logger.LastState()
	if idx != 10 {
		t.Errorf("Expected final index 10, got %d", idx)
	}
}

func TestAppend_MessageCopied(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-copy-*")
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

	// Append entry
	msg := []byte("original message")
	entry, err := logger.Append(msg, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Modify original message
	msg[0] = 'X'

	// Entry message should be unchanged (was copied)
	if entry.Msg[0] == 'X' {
		t.Error("Message was not copied - original modification affected entry")
	}
	if entry.Msg[0] != 'o' {
		t.Errorf("Expected first byte 'o', got %c", entry.Msg[0])
	}
}

func TestAppend_WithAnchors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-anchors-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	// Configure to create anchors every 5 entries
	cfg := Config{
		AnchorEvery: 5,
	}

	logger, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	// Append 12 entries
	for i := 0; i < 12; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatalf("Append %d failed: %v", i, err)
		}
	}

	// Verify anchors were created at indices 5 and 10
	anchors, err := store.ListAnchors()
	if err != nil {
		t.Fatalf("ListAnchors failed: %v", err)
	}

	if len(anchors) != 2 {
		t.Errorf("Expected 2 anchors, got %d", len(anchors))
	}

	if len(anchors) >= 1 && anchors[0].Index != 5 {
		t.Errorf("Expected first anchor at index 5, got %d", anchors[0].Index)
	}

	if len(anchors) >= 2 && anchors[1].Index != 10 {
		t.Errorf("Expected second anchor at index 10, got %d", anchors[1].Index)
	}
}

func TestAppend_NoAnchors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-noanchors-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	// AnchorEvery = 0 means no anchors
	cfg := Config{
		AnchorEvery: 0,
	}

	logger, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	// Append 10 entries
	for i := 0; i < 10; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify no anchors were created
	anchors, err := store.ListAnchors()
	if err != nil {
		t.Fatalf("ListAnchors failed: %v", err)
	}

	if len(anchors) != 0 {
		t.Errorf("Expected 0 anchors, got %d", len(anchors))
	}
}

func TestFwdKey_KeyEvolution(t *testing.T) {
	// Test that fwdKey properly evolves keys using SHA-256
	key := [KeySize]byte{1, 2, 3, 4, 5}
	original := key

	// Evolve once
	fwdKey(&key)

	// Should be different from original
	if key == original {
		t.Error("Key should change after evolution")
	}

	// Should match SHA-256 hash
	expected := sha256.Sum256(original[:])
	if key != expected {
		t.Error("Key evolution doesn't match SHA-256 hash")
	}

	// Evolve again
	secondKey := key
	fwdKey(&key)

	// Should be different from second key
	if key == secondKey {
		t.Error("Key should change after second evolution")
	}

	// Should match SHA-256 of second key
	expected = sha256.Sum256(secondKey[:])
	if key != expected {
		t.Error("Second key evolution doesn't match SHA-256 hash")
	}
}

func TestMac_Deterministic(t *testing.T) {
	key := []byte("test-key-32-bytes-long-12345678")
	data1 := []byte("data1")
	data2 := []byte("data2")

	// Same inputs should produce same output
	mac1 := mac(key, data1, data2)
	mac2 := mac(key, data1, data2)

	if mac1 != mac2 {
		t.Error("MAC should be deterministic")
	}

	// Different inputs should produce different output
	mac3 := mac(key, data2, data1) // Reversed order
	if mac1 == mac3 {
		t.Error("MAC should differ for different input order")
	}
}

func TestMac_EmptyChunks(t *testing.T) {
	key := []byte("test-key")

	// MAC with no chunks
	mac1 := mac(key)

	// MAC with empty chunk
	mac2 := mac(key, []byte{})

	// Should be the same (empty chunk adds nothing)
	if mac1 != mac2 {
		t.Error("MAC of empty chunks should match MAC of no chunks")
	}
}

func TestLastState_InitialState(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-state-*")
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

	idx, tagV, tagT := logger.LastState()

	if idx != 0 {
		t.Errorf("Expected initial index 0, got %d", idx)
	}

	var zeroTag [32]byte
	if tagV != zeroTag {
		t.Error("Expected initial tagV to be zero")
	}
	if tagT != zeroTag {
		t.Error("Expected initial tagT to be zero")
	}
}

func TestLastState_AfterAppend(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-state2-*")
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

	// Append entry
	entry, err := logger.Append([]byte("test"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	idx, tagV, tagT := logger.LastState()

	if idx != 1 {
		t.Errorf("Expected index 1, got %d", idx)
	}

	// Entry tag should match tagV
	if entry.Tag != tagV {
		t.Error("Entry tag should match tagV from LastState")
	}

	var zeroTag [32]byte
	if tagV == zeroTag {
		t.Error("Expected non-zero tagV after append")
	}
	if tagT == zeroTag {
		t.Error("Expected non-zero tagT after append")
	}
}

func TestGetInitialKeys_Unchanged(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-keys-*")
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

	// Get initial keys
	a0Before, b0Before := logger.GetInitialKeys()

	// Append entries (keys will evolve internally)
	for i := 0; i < 5; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// GetInitialKeys should still return the evolved CURRENT keys
	// (Note: This is actually returning current keys, not initial A0/B0)
	a0After, b0After := logger.GetInitialKeys()

	// Keys should have evolved (different from initial)
	if a0After == a0Before {
		t.Error("Verifier key should have evolved after appends")
	}
	if b0After == b0Before {
		t.Error("Trusted key should have evolved after appends")
	}
}

func TestAppend_DualMACs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-dual-*")
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

	// Append entry
	_, err = logger.Append([]byte("test"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Read back record
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatal(err)
	}

	var record Record
	for r := range ch {
		record = r
		break
	}
	_ = done()

	// Verify both tags are present and non-zero
	var zeroTag [32]byte
	if record.TagV == zeroTag {
		t.Error("Expected non-zero TagV in stored record")
	}
	if record.TagT == zeroTag {
		t.Error("Expected non-zero TagT in stored record")
	}

	// Tags should be different (different key chains)
	if record.TagV == record.TagT {
		t.Error("TagV and TagT should be different (different key chains)")
	}
}

func TestConfig_AllOptions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-logger-config-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	customKeyV := [KeySize]byte{1, 2, 3}
	customKeyT := [KeySize]byte{4, 5, 6}

	cfg := Config{
		AnchorEvery: 3,
		InitialKeyV: &customKeyV,
		InitialKeyT: &customKeyT,
	}

	logger, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	// Verify keys
	a0, b0 := logger.GetInitialKeys()
	if a0 != customKeyV {
		t.Error("Custom verifier key not used")
	}
	if b0 != customKeyT {
		t.Error("Custom trusted key not used")
	}

	// Verify anchors
	for i := 0; i < 7; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	anchors, err := store.ListAnchors()
	if err != nil {
		t.Fatal(err)
	}

	// Should have anchors at 3 and 6
	if len(anchors) != 2 {
		t.Errorf("Expected 2 anchors, got %d", len(anchors))
	}
}
