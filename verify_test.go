package securelog

import (
	"os"
	"testing"
	"time"
)

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []byte
		b    []byte
		want bool
	}{
		{
			name: "equal slices",
			a:    []byte{1, 2, 3, 4},
			b:    []byte{1, 2, 3, 4},
			want: true,
		},
		{
			name: "different slices",
			a:    []byte{1, 2, 3, 4},
			b:    []byte{1, 2, 3, 5},
			want: false,
		},
		{
			name: "different lengths",
			a:    []byte{1, 2, 3},
			b:    []byte{1, 2, 3, 4},
			want: false,
		},
		{
			name: "empty slices",
			a:    []byte{},
			b:    []byte{},
			want: true,
		},
		{
			name: "one empty",
			a:    []byte{1},
			b:    []byte{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := constantTimeEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("constantTimeEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyChain_Errors(t *testing.T) {
	// Test with gap in indices
	// Note: The function checks tags first, so we need to create valid records
	// to reach the gap detection code

	tmpDir, err := os.MkdirTemp("", "securelog-gap-*")
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

	a0, _ := logger.GetInitialKeys()

	// Append one entry
	_, err = logger.Append([]byte("test1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Read it back
	ch, done, err := store.Iter(1)
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	for r := range ch {
		records = append(records, r)
	}
	_ = done()

	// Manually modify the index to create a gap
	if len(records) > 0 {
		records[0].Index = 5 // Change from 1 to 5 - creates gap
	}

	var zeroTag [32]byte
	_, err = VerifyFrom(records, 0, a0, zeroTag)
	if err != ErrGap {
		t.Errorf("Expected ErrGap, got: %v", err)
	}
}
