package securelog

import (
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	pb "github.com/karasz/securelog/proto"
	"google.golang.org/protobuf/proto"
)

// Server provides HTTPS endpoints for the trusted server T.
// It receives commitments, closures, and log files for verification.
type Server struct {
	TrustedServer *TrustedServer
	mu            sync.RWMutex
	stores        map[string]Store // Map of logID -> Store for verification
	tlsConfig     *tls.Config
}

// NewServer creates a new HTTPS server for trusted server T.
func NewServer() *Server {
	return &Server{
		TrustedServer: NewTrustedServer(),
		stores:        make(map[string]Store),
	}
}

// SetTLSConfig clones cfg and stores it for use when serving HTTPS requests.
// If cfg is nil a default configuration will be used.
func (s *Server) SetTLSConfig(cfg *tls.Config) {
	if cfg == nil {
		s.tlsConfig = nil
		return
	}
	s.tlsConfig = cfg.Clone()
}

// RegisterStore associates a log ID with its storage backend.
// Required before verification can be performed.
func (s *Server) RegisterStore(logID string, store Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stores[logID] = store
}

// isProtobuf checks if the request content type is protobuf.
func isProtobuf(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, "application/x-protobuf") ||
		strings.HasPrefix(contentType, "application/protobuf")
}

// decodeInitCommitment decodes InitCommitment from either Gob or Protobuf.
func decodeInitCommitment(r *http.Request) (InitCommitment, error) {
	if isProtobuf(r) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return InitCommitment{}, fmt.Errorf("read body: %w", err)
		}
		var pbCommit pb.InitCommitment
		if err := proto.Unmarshal(body, &pbCommit); err != nil {
			return InitCommitment{}, fmt.Errorf("unmarshal protobuf: %w", err)
		}
		return FromProtoInitCommitment(&pbCommit)
	}

	// Default to Gob for backward compatibility
	var commit InitCommitment
	if err := gob.NewDecoder(r.Body).Decode(&commit); err != nil {
		return InitCommitment{}, fmt.Errorf("decode gob: %w", err)
	}
	return commit, nil
}

// decodeOpenMessage decodes OpenMessage from either Gob or Protobuf.
func decodeOpenMessage(r *http.Request) (OpenMessage, error) {
	if isProtobuf(r) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return OpenMessage{}, fmt.Errorf("read body: %w", err)
		}
		var pbOpen pb.OpenMessage
		if err := proto.Unmarshal(body, &pbOpen); err != nil {
			return OpenMessage{}, fmt.Errorf("unmarshal protobuf: %w", err)
		}
		return FromProtoOpenMessage(&pbOpen)
	}

	// Default to Gob
	var open OpenMessage
	if err := gob.NewDecoder(r.Body).Decode(&open); err != nil {
		return OpenMessage{}, fmt.Errorf("decode gob: %w", err)
	}
	return open, nil
}

// decodeCloseMessage decodes CloseMessage from either Gob or Protobuf.
func decodeCloseMessage(r *http.Request) (CloseMessage, error) {
	if isProtobuf(r) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return CloseMessage{}, fmt.Errorf("read body: %w", err)
		}
		var pbClose pb.CloseMessage
		if err := proto.Unmarshal(body, &pbClose); err != nil {
			return CloseMessage{}, fmt.Errorf("unmarshal protobuf: %w", err)
		}
		return FromProtoCloseMessage(&pbClose)
	}

	// Default to Gob
	var closeMsg CloseMessage
	if err := gob.NewDecoder(r.Body).Decode(&closeMsg); err != nil {
		return CloseMessage{}, fmt.Errorf("decode gob: %w", err)
	}
	return closeMsg, nil
}

// decodeVerifyRequest decodes verify request from either Gob or Protobuf.
func decodeVerifyRequest(r *http.Request) (string, []Record, error) {
	// Extract logID from path
	logID := r.URL.Path[len("/api/v1/logs/"):]
	logID = logID[:len(logID)-len("/verify")]

	if isProtobuf(r) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return "", nil, fmt.Errorf("read body: %w", err)
		}
		var pbReq pb.VerifyRequest
		if err := proto.Unmarshal(body, &pbReq); err != nil {
			return "", nil, fmt.Errorf("unmarshal protobuf: %w", err)
		}
		records, err := FromProtoRecords(pbReq.Records)
		if err != nil {
			return "", nil, fmt.Errorf("convert records: %w", err)
		}
		return pbReq.LogId, records, nil
	}

	// Default to Gob
	var records []Record
	if err := gob.NewDecoder(r.Body).Decode(&records); err != nil {
		return "", nil, fmt.Errorf("decode gob: %w", err)
	}
	return logID, records, nil
}

// encodeVerifyResponse encodes verify response in the appropriate format.
func encodeVerifyResponse(w http.ResponseWriter, r *http.Request, logID string, verified bool, errMsg string) error {
	if isProtobuf(r) {
		resp := &pb.VerifyResponse{
			Verified:     verified,
			ErrorMessage: errMsg,
		}
		data, err := proto.Marshal(resp)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(data)
		return err
	}

	// Default to JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(map[string]any{
		"status":   "verified",
		"log_id":   logID,
		"verified": verified,
	})
}

// HandleRegister handles POST /api/v1/logs/register - initial commitment.
// Supports both Gob and Protocol Buffer encoding.
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	commit, err := decodeInitCommitment(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid commitment: %v", err), http.StatusBadRequest)
		return
	}

	s.TrustedServer.RegisterLog(commit)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "registered",
		"log_id": commit.LogID,
	})
}

// HandleOpen handles POST /api/v1/logs/open - log opening notification.
// Supports both Gob and Protocol Buffer encoding.
func (s *Server) HandleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	open, err := decodeOpenMessage(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid open message: %v", err), http.StatusBadRequest)
		return
	}

	s.TrustedServer.RegisterOpen(open)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "opened",
		"log_id": open.LogID,
	})
}

// HandleClose handles POST /api/v1/logs/close - log closure notification.
// Supports both Gob and Protocol Buffer encoding.
func (s *Server) HandleClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	closeMsg, err := decodeCloseMessage(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid closure: %v", err), http.StatusBadRequest)
		return
	}

	if err := s.TrustedServer.AcceptClosure(closeMsg); err != nil {
		http.Error(w, fmt.Sprintf("Accept closure failed: %v", err), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "closed",
		"log_id": closeMsg.LogID,
	})
}

// HandleVerify handles POST /api/v1/logs/{logID}/verify - final verification.
// Supports both Gob and Protocol Buffer encoding.
func (s *Server) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logID, records, err := decodeVerifyRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}

	// Perform verification
	if err := s.TrustedServer.FinalVerify(logID, records); err != nil {
		// Send error response in appropriate format
		if encErr := encodeVerifyResponse(w, r, logID, false, err.Error()); encErr != nil {
			http.Error(w, fmt.Sprintf("Verification failed: %v", err), http.StatusUnauthorized)
		}
		return
	}

	// Send success response
	if err := encodeVerifyResponse(w, r, logID, true, ""); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
	}
}

// SetupRoutes configures HTTP routes for the trusted server.
func (s *Server) SetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/logs/register", s.HandleRegister)
	mux.HandleFunc("/api/v1/logs/open", s.HandleOpen)
	mux.HandleFunc("/api/v1/logs/close", s.HandleClose)
	mux.HandleFunc("/api/v1/logs/", s.HandleVerify) // Catch-all for verify
}

func (s *Server) tlsConfigWithDefaults() *tls.Config {
	if s.tlsConfig == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg := s.tlsConfig.Clone()
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	return cfg
}

// ListenAndServeTLS starts the HTTPS server for trusted server T.
func (s *Server) ListenAndServeTLS(addr, certFile, keyFile string) error {
	mux := http.NewServeMux()
	s.SetupRoutes(mux)
	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: s.tlsConfigWithDefaults(),
	}
	return server.ListenAndServeTLS(certFile, keyFile)
}
