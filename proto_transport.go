package securelog

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	pb "github.com/karasz/securelog/proto"
	"google.golang.org/protobuf/proto"
)

// ProtoHTTPTransport implements Transport using Protocol Buffers over HTTP/HTTPS.
// This is more efficient than Gob and language-agnostic.
type ProtoHTTPTransport struct {
	BaseURL string       // Base URL of trusted server (e.g., "https://trust.example.com")
	Client  *http.Client // HTTP client (can customize timeouts, TLS, etc.)
}

// NewProtoHTTPTransport creates a new Protocol Buffer HTTP transport.
func NewProtoHTTPTransport(baseURL string) *ProtoHTTPTransport {
	return &ProtoHTTPTransport{
		BaseURL: baseURL,
		Client:  &http.Client{},
	}
}

// SendCommitment sends the initial commitment via HTTP POST using protobuf.
func (t *ProtoHTTPTransport) SendCommitment(commit InitCommitment) error {
	pbMsg := ToProtoInitCommitment(commit)
	data, err := proto.Marshal(pbMsg)
	if err != nil {
		return fmt.Errorf("marshal commitment: %w", err)
	}

	url := t.BaseURL + "/api/v1/logs/register"
	resp, err := t.Client.Post(url, "application/x-protobuf", bytes.NewReader(data))
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

// SendOpen sends the opening message via HTTP POST using protobuf.
func (t *ProtoHTTPTransport) SendOpen(open OpenMessage) error {
	pbMsg := ToProtoOpenMessage(open)
	data, err := proto.Marshal(pbMsg)
	if err != nil {
		return fmt.Errorf("marshal open message: %w", err)
	}

	url := t.BaseURL + "/api/v1/logs/open"
	resp, err := t.Client.Post(url, "application/x-protobuf", bytes.NewReader(data))
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

// SendClosure sends the closure message via HTTP POST using protobuf.
func (t *ProtoHTTPTransport) SendClosure(closeMsg CloseMessage) error {
	pbMsg := ToProtoCloseMessage(closeMsg)
	data, err := proto.Marshal(pbMsg)
	if err != nil {
		return fmt.Errorf("marshal closure: %w", err)
	}

	url := t.BaseURL + "/api/v1/logs/close"
	resp, err := t.Client.Post(url, "application/x-protobuf", bytes.NewReader(data))
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

// SendLogFile sends the complete log file for verification using protobuf.
func (t *ProtoHTTPTransport) SendLogFile(logID string, records []Record) (bool, error) {
	req := &pb.VerifyRequest{
		LogId:   logID,
		Records: ToProtoRecords(records),
	}

	data, err := proto.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("marshal verify request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/logs/%s/verify", t.BaseURL, logID)
	resp, err := t.Client.Post(url, "application/x-protobuf", bytes.NewReader(data))
	if err != nil {
		return false, fmt.Errorf("post log file: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("read response: %w", err)
	}

	var verifyResp pb.VerifyResponse
	if err := proto.Unmarshal(body, &verifyResp); err != nil {
		return false, fmt.Errorf("unmarshal verify response: %w", err)
	}

	if !verifyResp.Verified {
		return false, fmt.Errorf("verification failed: %s", verifyResp.ErrorMessage)
	}

	return true, nil
}
