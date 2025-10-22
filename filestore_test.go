package securelog

import (
	"os"
	"testing"
	"time"
)

//revive:disable:cyclomatic High complexity acceptable in tests
//revive:disable:cognitive-complexity High complexity acceptable in tests
//revive:disable:function-length Long test functions are acceptable

func TestFileStore_AnchorAt(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-anchor-*")
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

	// Append entries to create anchors
	for i := 0; i < 25; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Test getting existing anchor
	anchor, found, err := store.AnchorAt(10)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("Expected anchor at 10")
	}
	if anchor.Index != 10 {
		t.Errorf("Expected anchor index 10, got %d", anchor.Index)
	}

	// Test getting another anchor
	anchor, found, err = store.AnchorAt(20)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("Expected anchor at 20")
	}
	if anchor.Index != 20 {
		t.Errorf("Expected anchor index 20, got %d", anchor.Index)
	}

	// Test getting non-existent anchor
	_, found, err = store.AnchorAt(15)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("Should not find anchor at 15")
	}

	// Test getting anchor beyond what exists
	_, found, err = store.AnchorAt(100)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("Should not find anchor at 100")
	}
}

func TestFileStore_ErrorCases(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-errors-*")
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
	_, err = logger.Append([]byte("first"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Try to manually append non-contiguous record
	rec := Record{
		Index: 10, // Gap!
		TS:    time.Now().UnixNano(),
		Msg:   []byte("test"),
	}
	var tail TailState
	tail.Index = rec.Index

	err = store.Append(rec, tail, nil)
	if err == nil {
		t.Error("Expected error for non-contiguous append")
	}
}

func TestFileStore_Close(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-close-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	fs := store.(*fileStore)

	// Add some data
	logger, err := New(Config{}, store)
	if err != nil {
		t.Fatal(err)
	}

	_, err = logger.Append([]byte("test"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Close the store
	err = fs.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Subsequent operations should fail or handle closed files
	// (though the current implementation doesn't check for closed state)
}

func TestFileStore_EmptyDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-empty-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	// Test iteration on empty store
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for range ch {
		count++
	}
	_ = done()

	if count != 0 {
		t.Errorf("Expected 0 records in empty store, got %d", count)
	}

	// Test getting tail from empty store
	_, ok, err := store.Tail()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("Should not have tail in empty store")
	}

	// Test ListAnchors on empty store
	anchors, err := store.ListAnchors()
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 0 {
		t.Errorf("Expected 0 anchors, got %d", len(anchors))
	}
}

func TestFileStore_CustomInitialKeys(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-keys-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := OpenFileStore(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*fileStore).Close()

	// Test with custom initial keys
	var customKeyV, customKeyT [KeySize]byte
	customKeyV[0] = 0xAA
	customKeyT[0] = 0xBB

	cfg := Config{
		AnchorEvery: 5,
		InitialKeyV: &customKeyV,
		InitialKeyT: &customKeyT,
	}

	logger, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}

	a0, b0 := logger.GetInitialKeys()
	if a0[0] != 0xAA {
		t.Error("InitialKeyV not set correctly")
	}
	if b0[0] != 0xBB {
		t.Error("InitialKeyT not set correctly")
	}

	// Append and verify
	_, err = logger.Append([]byte("test"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
}
