package securelog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStore_Iter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-sqlite-iter-*")
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
	for i := 0; i < 10; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Test iteration
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for r := range ch {
		count++
		if r.Index < 1 {
			t.Errorf("Invalid index: %d", r.Index)
		}
	}
	_ = done()

	if count != 10 {
		t.Errorf("Expected 10 records, got %d", count)
	}

	// Test iteration from middle
	ch, done, err = store.Iter(5)
	if err != nil {
		t.Fatal(err)
	}

	count = 0
	for r := range ch {
		count++
		if r.Index < 5 {
			t.Errorf("Index %d should be >= 5", r.Index)
		}
	}
	_ = done()

	if count != 6 {
		t.Errorf("Expected 6 records from index 5, got %d", count)
	}
}

func TestSQLiteStore_AnchorAt(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-sqlite-anchor-*")
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

	// Append entries to create anchors
	for i := 0; i < 15; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Test getting existing anchor
	anchor, found, err := store.AnchorAt(5)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("Expected anchor at 5")
	}
	if anchor.Index != 5 {
		t.Errorf("Expected anchor index 5, got %d", anchor.Index)
	}

	// Test getting non-existent anchor
	_, found, err = store.AnchorAt(3)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("Should not find anchor at 3")
	}
}

func TestSQLiteStore_Tail(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-sqlite-tail-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := OpenSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteStore failed: %v", err)
	}

	// Test empty store
	_, ok, err := store.Tail()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("Should not have tail in empty store")
	}

	// Add some entries
	logger, err := New(Config{}, store)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		_, err := logger.Append([]byte("test"), time.Now())
		if err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	// Test tail after entries
	tail, ok, err := store.Tail()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("Expected tail state")
	}
	if tail.Index != 5 {
		t.Errorf("Expected tail index 5, got %d", tail.Index)
	}
}

func TestSQLiteStore_InvalidAnchorData(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-sqlite-invalid-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := OpenSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteStore failed: %v", err)
	}

	sqlStore := store.(*sqliteStore)

	// Manually insert invalid anchor with wrong sizes
	_, err = sqlStore.db.Exec(`INSERT INTO anchors(idx, key, tagV, tagT) VALUES(?, ?, ?, ?)`,
		1, []byte{1, 2, 3}, []byte{4, 5}, []byte{6})
	if err != nil {
		t.Fatal(err)
	}

	// Try to read it - should fail
	_, _, err = store.AnchorAt(1)
	if err == nil {
		t.Error("Expected error reading invalid anchor")
	}
}
