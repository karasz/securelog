package securelog

import (
	"bytes"
	"testing"
	"time"

	pb "github.com/karasz/securelog/proto"
	"google.golang.org/protobuf/proto"
)

func TestInitCommitmentProtoConversion(t *testing.T) {
	now := time.Now()
	var keyA0, keyB0 [KeySize]byte
	for i := range keyA0 {
		keyA0[i] = byte(i)
		keyB0[i] = byte(i + 100)
	}

	original := InitCommitment{
		LogID:      "test-log-123",
		StartTime:  now,
		KeyA0:      keyA0,
		KeyB0:      keyB0,
		UpdateFreq: 1000,
	}

	// Convert to proto
	pbMsg := ToProtoInitCommitment(original)

	// Convert back
	converted, err := FromProtoInitCommitment(pbMsg)
	if err != nil {
		t.Fatalf("FromProtoInitCommitment failed: %v", err)
	}

	// Verify fields
	if converted.LogID != original.LogID {
		t.Errorf("LogID mismatch: got %s, want %s", converted.LogID, original.LogID)
	}
	if !converted.StartTime.Equal(original.StartTime) {
		t.Errorf("StartTime mismatch: got %v, want %v", converted.StartTime, original.StartTime)
	}
	if converted.KeyA0 != original.KeyA0 {
		t.Errorf("KeyA0 mismatch")
	}
	if converted.KeyB0 != original.KeyB0 {
		t.Errorf("KeyB0 mismatch")
	}
	if converted.UpdateFreq != original.UpdateFreq {
		t.Errorf("UpdateFreq mismatch: got %d, want %d", converted.UpdateFreq, original.UpdateFreq)
	}
}

func TestOpenMessageProtoConversion(t *testing.T) {
	now := time.Now()
	var tagV, tagT [32]byte
	for i := range tagV {
		tagV[i] = byte(i)
		tagT[i] = byte(i + 50)
	}

	original := OpenMessage{
		LogID:      "test-log-456",
		OpenTime:   now,
		FirstIndex: 1,
		FirstTagV:  tagV,
		FirstTagT:  tagT,
	}

	// Convert to proto
	pbMsg := ToProtoOpenMessage(original)

	// Convert back
	converted, err := FromProtoOpenMessage(pbMsg)
	if err != nil {
		t.Fatalf("FromProtoOpenMessage failed: %v", err)
	}

	// Verify fields
	if converted.LogID != original.LogID {
		t.Errorf("LogID mismatch")
	}
	if !converted.OpenTime.Equal(original.OpenTime) {
		t.Errorf("OpenTime mismatch")
	}
	if converted.FirstIndex != original.FirstIndex {
		t.Errorf("FirstIndex mismatch")
	}
	if converted.FirstTagV != original.FirstTagV {
		t.Errorf("FirstTagV mismatch")
	}
	if converted.FirstTagT != original.FirstTagT {
		t.Errorf("FirstTagT mismatch")
	}
}

func TestCloseMessageProtoConversion(t *testing.T) {
	now := time.Now()
	var tagV, tagT [32]byte
	for i := range tagV {
		tagV[i] = byte(255 - i)
		tagT[i] = byte(128 + i)
	}

	original := CloseMessage{
		LogID:      "test-log-789",
		CloseTime:  now,
		FinalIndex: 1000,
		FinalTagV:  tagV,
		FinalTagT:  tagT,
	}

	// Convert to proto
	pbMsg := ToProtoCloseMessage(original)

	// Convert back
	converted, err := FromProtoCloseMessage(pbMsg)
	if err != nil {
		t.Fatalf("FromProtoCloseMessage failed: %v", err)
	}

	// Verify fields
	if converted.LogID != original.LogID {
		t.Errorf("LogID mismatch")
	}
	if !converted.CloseTime.Equal(original.CloseTime) {
		t.Errorf("CloseTime mismatch")
	}
	if converted.FinalIndex != original.FinalIndex {
		t.Errorf("FinalIndex mismatch")
	}
	if converted.FinalTagV != original.FinalTagV {
		t.Errorf("FinalTagV mismatch")
	}
	if converted.FinalTagT != original.FinalTagT {
		t.Errorf("FinalTagT mismatch")
	}
}

func TestRecordProtoConversion(t *testing.T) {
	var tagV, tagT [32]byte
	for i := range tagV {
		tagV[i] = byte(i * 2)
		tagT[i] = byte(i * 3)
	}

	original := Record{
		Index: 42,
		TS:    time.Now().UnixNano(),
		Msg:   []byte("test message with special chars: \n\t\r"),
		TagV:  tagV,
		TagT:  tagT,
	}

	// Convert to proto
	pbMsg := ToProtoRecord(original)

	// Convert back
	converted, err := FromProtoRecord(pbMsg)
	if err != nil {
		t.Fatalf("FromProtoRecord failed: %v", err)
	}

	// Verify fields
	if converted.Index != original.Index {
		t.Errorf("Index mismatch")
	}
	if converted.TS != original.TS {
		t.Errorf("TS mismatch")
	}
	if !bytes.Equal(converted.Msg, original.Msg) {
		t.Errorf("Msg mismatch: got %q, want %q", converted.Msg, original.Msg)
	}
	if converted.TagV != original.TagV {
		t.Errorf("TagV mismatch")
	}
	if converted.TagT != original.TagT {
		t.Errorf("TagT mismatch")
	}
}

func TestRecordBatchProtoConversion(t *testing.T) {
	var tag1V, tag1T, tag2V, tag2T [32]byte
	for i := range tag1V {
		tag1V[i] = byte(i)
		tag1T[i] = byte(i + 1)
		tag2V[i] = byte(i + 2)
		tag2T[i] = byte(i + 3)
	}

	originals := []Record{
		{
			Index: 1,
			TS:    time.Now().UnixNano(),
			Msg:   []byte("first message"),
			TagV:  tag1V,
			TagT:  tag1T,
		},
		{
			Index: 2,
			TS:    time.Now().UnixNano(),
			Msg:   []byte("second message"),
			TagV:  tag2V,
			TagT:  tag2T,
		},
	}

	// Convert to proto
	pbRecords := ToProtoRecords(originals)

	// Convert back
	converted, err := FromProtoRecords(pbRecords)
	if err != nil {
		t.Fatalf("FromProtoRecords failed: %v", err)
	}

	// Verify
	if len(converted) != len(originals) {
		t.Fatalf("Length mismatch: got %d, want %d", len(converted), len(originals))
	}

	for i := range originals {
		if converted[i].Index != originals[i].Index {
			t.Errorf("Record %d: Index mismatch", i)
		}
		if !bytes.Equal(converted[i].Msg, originals[i].Msg) {
			t.Errorf("Record %d: Msg mismatch", i)
		}
	}
}

func TestProtoMarshalSize(t *testing.T) {
	// Test protobuf size vs gob for typical record
	var tagV, tagT [32]byte
	for i := range tagV {
		tagV[i] = byte(i)
		tagT[i] = byte(i + 100)
	}

	record := Record{
		Index: 12345,
		TS:    time.Now().UnixNano(),
		Msg:   []byte("This is a typical log message with some content"),
		TagV:  tagV,
		TagT:  tagT,
	}

	// Protobuf size
	pbRecord := ToProtoRecord(record)
	pbData, err := proto.Marshal(pbRecord)
	if err != nil {
		t.Fatalf("proto.Marshal failed: %v", err)
	}

	t.Logf("Protobuf size for single record: %d bytes", len(pbData))
	t.Logf("Message size: %d bytes", len(record.Msg))
	t.Logf("Overhead: %d bytes", len(pbData)-len(record.Msg))

	// Verify it unmarshals correctly
	var decoded pb.Record
	if err := proto.Unmarshal(pbData, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal failed: %v", err)
	}

	if decoded.Index != record.Index {
		t.Errorf("Decoded index mismatch")
	}
}

func TestInvalidProtoData(t *testing.T) {
	tests := []struct {
		name    string
		build   func() *pb.Record
		wantErr bool
	}{
		{
			name: "invalid TagV size",
			build: func() *pb.Record {
				return &pb.Record{
					Index: 1,
					Ts:    time.Now().UnixNano(),
					Msg:   []byte("test"),
					TagV:  []byte{1, 2, 3}, // Too short
					TagT:  make([]byte, 32),
				}
			},
			wantErr: true,
		},
		{
			name: "invalid TagT size",
			build: func() *pb.Record {
				return &pb.Record{
					Index: 1,
					Ts:    time.Now().UnixNano(),
					Msg:   []byte("test"),
					TagV:  make([]byte, 32),
					TagT:  make([]byte, 100), // Too long
				}
			},
			wantErr: true,
		},
		{
			name: "valid record",
			build: func() *pb.Record {
				return &pb.Record{
					Index: 1,
					Ts:    time.Now().UnixNano(),
					Msg:   []byte("test"),
					TagV:  make([]byte, 32),
					TagT:  make([]byte, 32),
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pbRecord := tt.build()
			_, err := FromProtoRecord(pbRecord)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromProtoRecord() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
