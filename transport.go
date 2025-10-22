package securelog

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// Transport defines how data is sent to the trusted server T.
// Different implementations can use HTTP, gRPC, message queues, etc.
type Transport interface {
	// SendCommitment sends initial log commitment to trusted server
	SendCommitment(commit InitCommitment) error

	// SendOpen sends log opening metadata to trusted server
	SendOpen(open OpenMessage) error

	// SendClosure sends log closure notification to trusted server
	SendClosure(closeMsg CloseMessage) error

	// SendLogFile sends complete log file for final verification
	// Returns true if verification passed
	SendLogFile(logID string, records []Record) (bool, error)
}

// HTTPTransport implements Transport using HTTP/HTTPS.
type HTTPTransport struct {
	BaseURL string       // Base URL of trusted server (e.g., "https://trust.example.com")
	Client  *http.Client // HTTP client (can customize timeouts, TLS, etc.)
}

// NewHTTPTransport creates a new HTTP transport for communicating with trusted server.
func NewHTTPTransport(baseURL string) *HTTPTransport {
	return &HTTPTransport{
		BaseURL: baseURL,
		Client:  &http.Client{},
	}
}

// SendCommitment sends the initial commitment via HTTP POST.
func (t *HTTPTransport) SendCommitment(commit InitCommitment) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(commit); err != nil {
		return fmt.Errorf("encode commitment: %w", err)
	}

	url := t.BaseURL + "/api/v1/logs/register"
	resp, err := t.Client.Post(url, "application/octet-stream", &buf)
	if err != nil {
		return fmt.Errorf("post commitment: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}

	return nil
}

// SendOpen sends the opening message via HTTP POST.
func (t *HTTPTransport) SendOpen(open OpenMessage) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(open); err != nil {
		return fmt.Errorf("encode open message: %w", err)
	}

	url := t.BaseURL + "/api/v1/logs/open"
	resp, err := t.Client.Post(url, "application/octet-stream", &buf)
	if err != nil {
		return fmt.Errorf("post open message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}

	return nil
}

// SendClosure sends the closure message via HTTP POST.
func (t *HTTPTransport) SendClosure(closeMsg CloseMessage) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(closeMsg); err != nil {
		return fmt.Errorf("encode closure: %w", err)
	}

	url := t.BaseURL + "/api/v1/logs/close"
	resp, err := t.Client.Post(url, "application/octet-stream", &buf)
	if err != nil {
		return fmt.Errorf("post closure: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}

	return nil
}

// SendLogFile sends the complete log file for verification.
func (t *HTTPTransport) SendLogFile(logID string, records []Record) (bool, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(records); err != nil {
		return false, fmt.Errorf("encode records: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/logs/%s/verify", t.BaseURL, logID)
	resp, err := t.Client.Post(url, "application/octet-stream", &buf)
	if err != nil {
		return false, fmt.Errorf("post log file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil // Verification passed
	}

	body, _ := io.ReadAll(resp.Body)
	return false, fmt.Errorf("verification failed: %s", body)
}

// LocalTransport is a Transport that communicates with an in-process TrustedServer.
// Useful for testing or single-machine deployments where U and T are co-located.
type LocalTransport struct {
	Server *TrustedServer
	Store  Store // Access to log storage for verification
}

// NewLocalTransport creates a transport that communicates with a local TrustedServer.
func NewLocalTransport(server *TrustedServer, store Store) *LocalTransport {
	return &LocalTransport{
		Server: server,
		Store:  store,
	}
}

// SendCommitment registers the log with the local trusted server.
func (t *LocalTransport) SendCommitment(commit InitCommitment) error {
	t.Server.RegisterLog(commit)
	return nil
}

// SendOpen sends the open message to the local trusted server.
func (t *LocalTransport) SendOpen(open OpenMessage) error {
	t.Server.RegisterOpen(open)
	return nil
}

// SendClosure sends closure to the local trusted server.
func (t *LocalTransport) SendClosure(closeMsg CloseMessage) error {
	return t.Server.AcceptClosure(closeMsg)
}

// SendLogFile performs verification using the local trusted server.
func (t *LocalTransport) SendLogFile(logID string, records []Record) (bool, error) {
	err := t.Server.FinalVerify(logID, records)
	return err == nil, err
}

// FolderTransport writes commitments, closures, and logs to a local folder structure.
// This enables self-contained deployments where T is a local directory.
// Folder structure:
//
//	{dir}/commitments/{logID}.gob - InitCommitment
//	{dir}/closures/{logID}.gob - CloseMessage
//	{dir}/logs/{logID}/ - Log file storage (uses file_store.go)
type FolderTransport struct {
	BaseDir string
	mu      sync.Mutex
}

// NewFolderTransport creates a new folder-based transport.
// Creates directory structure: commitments/, closures/, logs/
func NewFolderTransport(dir string) (*FolderTransport, error) {
	// Create directory structure
	dirs := []string{
		filepath.Join(dir, "commitments"),
		filepath.Join(dir, "opens"),
		filepath.Join(dir, "closures"),
		filepath.Join(dir, "logs"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, err
		}
	}
	return &FolderTransport{BaseDir: dir}, nil
}

// SendCommitment writes commitment to {BaseDir}/commitments/{logID}.gob
func (ft *FolderTransport) SendCommitment(commit InitCommitment) error {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	path := filepath.Join(ft.BaseDir, "commitments", commit.LogID+".gob")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := gob.NewEncoder(f)
	return enc.Encode(commit)
}

// SendOpen writes open message to {BaseDir}/opens/{logID}.gob
func (ft *FolderTransport) SendOpen(open OpenMessage) error {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	path := filepath.Join(ft.BaseDir, "opens", open.LogID+".gob")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := gob.NewEncoder(f)
	return enc.Encode(open)
}

// SendClosure writes closure to {BaseDir}/closures/{logID}.gob
func (ft *FolderTransport) SendClosure(closeMsg CloseMessage) error {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	path := filepath.Join(ft.BaseDir, "closures", closeMsg.LogID+".gob")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := gob.NewEncoder(f)
	return enc.Encode(closeMsg)
}

// SendLogFile verifies the log exists in the shared folder structure
func (ft *FolderTransport) SendLogFile(logID string, _ []Record) (bool, error) {
	// For folder transport, logs are already stored in the shared folder structure
	// This method just verifies the log exists
	logDir := filepath.Join(ft.BaseDir, "logs", logID)
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		return false, errors.New("log directory not found")
	}
	return true, nil
}

// LoadCommitment reads a commitment from {BaseDir}/commitments/{logID}.gob
func (ft *FolderTransport) LoadCommitment(logID string) (InitCommitment, error) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	path := filepath.Join(ft.BaseDir, "commitments", logID+".gob")
	f, err := os.Open(path)
	if err != nil {
		return InitCommitment{}, err
	}
	defer f.Close()

	var commit InitCommitment
	dec := gob.NewDecoder(f)
	if err := dec.Decode(&commit); err != nil {
		return InitCommitment{}, err
	}
	return commit, nil
}

// LoadOpen reads an opening message from {BaseDir}/opens/{logID}.gob
func (ft *FolderTransport) LoadOpen(logID string) (OpenMessage, error) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	path := filepath.Join(ft.BaseDir, "opens", logID+".gob")
	f, err := os.Open(path)
	if err != nil {
		return OpenMessage{}, err
	}
	defer f.Close()

	var open OpenMessage
	if err := gob.NewDecoder(f).Decode(&open); err != nil {
		return OpenMessage{}, err
	}
	return open, nil
}

// LoadClosure reads a closure from {BaseDir}/closures/{logID}.gob
func (ft *FolderTransport) LoadClosure(logID string) (CloseMessage, error) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	path := filepath.Join(ft.BaseDir, "closures", logID+".gob")
	f, err := os.Open(path)
	if err != nil {
		return CloseMessage{}, err
	}
	defer f.Close()

	var closeMsg CloseMessage
	dec := gob.NewDecoder(f)
	if err := dec.Decode(&closeMsg); err != nil {
		return CloseMessage{}, err
	}
	return closeMsg, nil
}

// GetLogStore returns a Store for reading the log records from {BaseDir}/logs/{logID}/
func (ft *FolderTransport) GetLogStore(logID string) (Store, error) {
	logDir := filepath.Join(ft.BaseDir, "logs", logID)
	return OpenFileStore(logDir)
}

// VerifyLog performs final T-chain verification for a log stored in the folder.
// This is the equivalent of TrustedServer.FinalVerify() for folder-based deployments.
func (ft *FolderTransport) VerifyLog(logID string) error {
	commit, err := ft.LoadCommitment(logID)
	if err != nil {
		return fmt.Errorf("load commitment: %w", err)
	}

	open, err := ft.LoadOpen(logID)
	if err != nil {
		return fmt.Errorf("load open message: %w", err)
	}

	closeMsg, err := ft.LoadClosure(logID)
	if err != nil {
		return fmt.Errorf("load closure: %w", err)
	}

	store, err := ft.GetLogStore(logID)
	if err != nil {
		return fmt.Errorf("open log store: %w", err)
	}

	ch, done, err := store.Iter(1)
	if err != nil {
		return fmt.Errorf("iterate records: %w", err)
	}
	var records []Record
	for r := range ch {
		records = append(records, r)
	}
	_ = done()

	if err := VerifyCloseMessage(records, closeMsg); err != nil {
		return fmt.Errorf("verify close message: %w", err)
	}

	if len(records) == 0 {
		return errors.New("no records to verify")
	}
	first := records[0]
	if first.Index != open.FirstIndex {
		return errors.New("opening index mismatch")
	}
	if string(first.Msg) != "START" {
		return errors.New("missing opening entry")
	}

	var zeroTag [32]byte
	firstV, err := VerifyFrom(records[:1], 0, commit.KeyA0, zeroTag)
	if err != nil {
		return fmt.Errorf("verify opening V-chain: %w", err)
	}
	firstT, err := VerifyFromTrusted(records[:1], 0, commit.KeyB0, zeroTag)
	if err != nil {
		return fmt.Errorf("verify opening T-chain: %w", err)
	}
	if !hmacEqual(firstV[:], open.FirstTagV[:]) || !hmacEqual(firstT[:], open.FirstTagT[:]) {
		return errors.New("opening tag mismatch")
	}

	finalTag, err := VerifyFromTrusted(records, 0, commit.KeyB0, zeroTag)
	if err != nil {
		return fmt.Errorf("verify T-chain: %w", err)
	}

	if !hmacEqual(finalTag[:], closeMsg.FinalTagT[:]) {
		return errors.New("final T-chain tag mismatch")
	}

	return nil
}

// hmacEqual is a helper for constant-time comparison
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// RemoteLogger wraps a Logger and automatically sends commitments/closures to T.
type RemoteLogger struct {
	*Logger
	LogID     string
	Transport Transport
	mu        sync.Mutex
	closed    bool
}

// NewRemoteLogger creates a logger that automatically communicates with trusted server T.
func NewRemoteLogger(cfg Config, store Store, transport Transport, logID string) (*RemoteLogger, error) {
	logger, err := New(cfg, store)
	if err != nil {
		return nil, err
	}

	rl := &RemoteLogger{
		Logger:    logger,
		LogID:     logID,
		Transport: transport,
	}

	commit, openMsg, err := logger.InitProtocol(logID)
	if err != nil {
		return nil, fmt.Errorf("init protocol: %w", err)
	}
	if err := transport.SendCommitment(commit); err != nil {
		return nil, fmt.Errorf("send initial commitment: %w", err)
	}
	if err := transport.SendOpen(openMsg); err != nil {
		return nil, fmt.Errorf("send open message: %w", err)
	}

	return rl, nil
}

// Close sends the closure message to trusted server T.
func (rl *RemoteLogger) Close() error {
	return rl.closeOnce()
}

func (rl *RemoteLogger) closeOnce() error {
	rl.mu.Lock()
	if rl.closed {
		rl.mu.Unlock()
		return nil
	}
	rl.mu.Unlock()

	closeMsg, err := rl.Logger.CloseProtocol(rl.LogID)
	if err != nil {
		return fmt.Errorf("create close message: %w", err)
	}

	if err := rl.Transport.SendClosure(closeMsg); err != nil {
		return fmt.Errorf("send closure: %w", err)
	}

	rl.mu.Lock()
	rl.closed = true
	rl.mu.Unlock()
	return nil
}
