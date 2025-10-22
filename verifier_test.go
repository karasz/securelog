package securelog

import (
	"os"
	"testing"
	"time"
)

func TestSemiTrustedVerifier(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-verifier-*")
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

	a0, _ := logger.GetInitialKeys()

	// Append entries
	for i := 0; i < 25; i++ {
		_, err := logger.Append([]byte("test message"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Create verifier
	verifier := NewSemiTrustedVerifier(store)

	// Verify from anchor
	anchor, found, err := store.AnchorAt(10)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("Expected anchor at 10")
	}

	err = verifier.VerifyFromAnchor(anchor)
	if err != nil {
		t.Fatalf("VerifyFromAnchor failed: %v", err)
	}

	// Also test from beginning
	err = verifier.VerifyFromAnchor(Anchor{
		Index: 0,
		Key:   a0,
		TagV:  [32]byte{},
		TagT:  [32]byte{},
	})
	if err != nil {
		t.Fatalf("VerifyFromAnchor from beginning failed: %v", err)
	}
}

func TestTrustedVerifier(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "securelog-trusted-*")
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

	_, b0 := logger.GetInitialKeys()

	// Append entries
	for i := 0; i < 25; i++ {
		_, err := logger.Append([]byte("test message"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}

	// Create trusted verifier
	verifier := NewTrustedVerifier(store, b0)

	// Verify all
	err = verifier.VerifyAll()
	if err != nil {
		t.Fatalf("VerifyAll failed: %v", err)
	}

	// Verify from beginning using B_0
	var zeroTag [32]byte
	err = verifier.VerifyFromAnchor(0, b0, zeroTag)
	if err != nil {
		t.Fatalf("VerifyFromAnchor from beginning failed: %v", err)
	}

	// Verify we can also check an anchor exists (even though we don't use it for T-chain)
	_, found, err := store.AnchorAt(10)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("Expected anchor at 10")
	}
}
