package securelog

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pb "github.com/karasz/securelog/proto"
	"google.golang.org/protobuf/proto"
)

func TestProtoHTTPTransport_SendCommitment(t *testing.T) {
	// Create test server
	var receivedCommit *pb.InitCommitment
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/logs/register" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Errorf("Unexpected content type: %s", r.Header.Get("Content-Type"))
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var commit pb.InitCommitment
		if err := proto.Unmarshal(body, &commit); err != nil {
			t.Errorf("Failed to unmarshal: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		receivedCommit = &commit
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create transport
	transport := NewProtoHTTPTransport(server.URL)

	// Create test commitment
	var keyA0, keyB0 [KeySize]byte
	for i := range keyA0 {
		keyA0[i] = byte(i)
		keyB0[i] = byte(i + 100)
	}

	commit := InitCommitment{
		LogID:      "test-log",
		StartTime:  time.Now(),
		KeyA0:      keyA0,
		KeyB0:      keyB0,
		UpdateFreq: 1000,
	}

	// Send commitment
	if err := transport.SendCommitment(commit); err != nil {
		t.Fatalf("SendCommitment failed: %v", err)
	}

	// Verify received data
	if receivedCommit == nil {
		t.Fatal("Server did not receive commitment")
	}
	if receivedCommit.LogId != commit.LogID {
		t.Errorf("LogID mismatch: got %s, want %s", receivedCommit.LogId, commit.LogID)
	}
}

func TestProtoHTTPTransport_SendOpen(t *testing.T) {
	var receivedOpen *pb.OpenMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/logs/open" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var open pb.OpenMessage
		if err := proto.Unmarshal(body, &open); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		receivedOpen = &open
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewProtoHTTPTransport(server.URL)

	var tagV, tagT [32]byte
	for i := range tagV {
		tagV[i] = byte(i)
		tagT[i] = byte(i + 50)
	}

	open := OpenMessage{
		LogID:      "test-log",
		OpenTime:   time.Now(),
		FirstIndex: 1,
		FirstTagV:  tagV,
		FirstTagT:  tagT,
	}

	if err := transport.SendOpen(open); err != nil {
		t.Fatalf("SendOpen failed: %v", err)
	}

	if receivedOpen == nil {
		t.Fatal("Server did not receive open message")
	}
	if receivedOpen.FirstIndex != open.FirstIndex {
		t.Errorf("FirstIndex mismatch")
	}
}

func TestProtoHTTPTransport_SendClosure(t *testing.T) {
	var receivedClose *pb.CloseMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/logs/close" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var closeMsg pb.CloseMessage
		if err := proto.Unmarshal(body, &closeMsg); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		receivedClose = &closeMsg
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewProtoHTTPTransport(server.URL)

	var tagV, tagT [32]byte
	for i := range tagV {
		tagV[i] = byte(255 - i)
		tagT[i] = byte(128 + i)
	}

	closeMsg := CloseMessage{
		LogID:      "test-log",
		CloseTime:  time.Now(),
		FinalIndex: 100,
		FinalTagV:  tagV,
		FinalTagT:  tagT,
	}

	if err := transport.SendClosure(closeMsg); err != nil {
		t.Fatalf("SendClosure failed: %v", err)
	}

	if receivedClose == nil {
		t.Fatal("Server did not receive close message")
	}
	if receivedClose.FinalIndex != closeMsg.FinalIndex {
		t.Errorf("FinalIndex mismatch")
	}
}

func TestProtoHTTPTransport_SendLogFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/logs/test-log/verify" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var req pb.VerifyRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Send success response
		resp := &pb.VerifyResponse{
			Verified:     true,
			ErrorMessage: "",
		}
		respData, _ := proto.Marshal(resp)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)
	}))
	defer server.Close()

	transport := NewProtoHTTPTransport(server.URL)

	var tagV, tagT [32]byte
	records := []Record{
		{
			Index: 1,
			TS:    time.Now().UnixNano(),
			Msg:   []byte("test message"),
			TagV:  tagV,
			TagT:  tagT,
		},
	}

	verified, err := transport.SendLogFile("test-log", records)
	if err != nil {
		t.Fatalf("SendLogFile failed: %v", err)
	}
	if !verified {
		t.Error("Expected verification to pass")
	}
}

func TestProtoHTTPTransport_SendLogFile_Failed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Send failure response
		resp := &pb.VerifyResponse{
			Verified:     false,
			ErrorMessage: "T-chain verification failed",
		}
		respData, _ := proto.Marshal(resp)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respData)
	}))
	defer server.Close()

	transport := NewProtoHTTPTransport(server.URL)

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

	verified, err := transport.SendLogFile("test-log", records)
	if err == nil {
		t.Fatal("Expected error for failed verification")
	}
	if verified {
		t.Error("Expected verification to fail")
	}
	if err.Error() != "verification failed: T-chain verification failed" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestProtoHTTPTransport_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	transport := NewProtoHTTPTransport(server.URL)

	var keyA0, keyB0 [KeySize]byte
	commit := InitCommitment{
		LogID:      "test-log",
		StartTime:  time.Now(),
		KeyA0:      keyA0,
		KeyB0:      keyB0,
		UpdateFreq: 1000,
	}

	err := transport.SendCommitment(commit)
	if err == nil {
		t.Fatal("Expected error for server error")
	}
	if err.Error() != "server returned 500: internal server error" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func BenchmarkProtoEncoding(b *testing.B) {
	var tagV, tagT [32]byte
	for i := range tagV {
		tagV[i] = byte(i)
		tagT[i] = byte(i + 100)
	}

	record := Record{
		Index: 12345,
		TS:    time.Now().UnixNano(),
		Msg:   []byte("This is a typical log message with some content that we want to benchmark"),
		TagV:  tagV,
		TagT:  tagT,
	}

	b.Run("Encode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			pbRecord := ToProtoRecord(record)
			_, err := proto.Marshal(pbRecord)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	pbRecord := ToProtoRecord(record)
	data, _ := proto.Marshal(pbRecord)

	b.Run("Decode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var decoded pb.Record
			if err := proto.Unmarshal(data, &decoded); err != nil {
				b.Fatal(err)
			}
			_, err := FromProtoRecord(&decoded)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkProtoBatchEncoding(b *testing.B) {
	// Create 100 records
	records := make([]Record, 100)
	for i := range records {
		var tagV, tagT [32]byte
		for j := range tagV {
			tagV[j] = byte(i + j)
			tagT[j] = byte(i + j + 100)
		}
		records[i] = Record{
			Index: uint64(i + 1),
			TS:    time.Now().UnixNano(),
			Msg:   []byte(fmt.Sprintf("Log message number %d with some content", i)),
			TagV:  tagV,
			TagT:  tagT,
		}
	}

	b.Run("EncodeBatch", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			pbRecords := ToProtoRecords(records)
			req := &pb.VerifyRequest{
				LogId:   "bench-test",
				Records: pbRecords,
			}
			_, err := proto.Marshal(req)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
