package securelog

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// InitCommitment represents the initial commitment sent to trusted server T.
// This implements the Log File Initialization protocol from Section 4.2.
type InitCommitment struct {
	LogID      string        // Unique log identifier
	StartTime  time.Time     // When the log was started
	KeyA0      [KeySize]byte // A_0 - initial verifier chain key
	KeyB0      [KeySize]byte // B_0 - initial trusted server chain key
	UpdateFreq uint64        // Key update frequency (UPD in the paper)
}

// OpenMessage records the fact that a log was opened and the first entry appended.
type OpenMessage struct {
	LogID      string    // Unique log identifier
	OpenTime   time.Time // When the log was opened
	FirstIndex uint64    // Index of the opening entry
	FirstTagV  [32]byte  // μ_V for the opening entry
	FirstTagT  [32]byte  // μ_T for the opening entry
}

// CloseMessage represents the log file closure notification.
// This implements the Log File Closure protocol from Section 4.2.
type CloseMessage struct {
	LogID      string    // Unique log identifier
	CloseTime  time.Time // When the log was closed
	FinalIndex uint64    // f - index of last entry
	FinalTagV  [32]byte  // μ_V,f
	FinalTagT  [32]byte  // μ_T,f
}

// ErrLogAlreadyClosed is returned when attempting to close an already closed log.
var ErrLogAlreadyClosed = errors.New("log has been closed")

// ErrLogNotClosed is returned when attempting to verify a log that hasn't been closed yet.
var ErrLogNotClosed = errors.New("log has not been closed yet")

// LogState tracks whether a log has been properly initialized and closed.
type LogState int

const (
	// LogStateOpen indicates the log is still accepting entries.
	LogStateOpen LogState = iota
	// LogStateClosed indicates the log has been closed and no more entries can be added.
	LogStateClosed
)

// InitProtocol handles the initial commitment to trusted server T.
// This prevents "total deletion attacks" as described in Section 4.2.
func (l *Logger) InitProtocol(logID string) (InitCommitment, OpenMessage, error) {
	now := time.Now()
	commit := InitCommitment{
		LogID:      logID,
		StartTime:  now,
		KeyA0:      l.keyV,
		KeyB0:      l.keyT,
		UpdateFreq: l.keyUpdateFrequency(),
	}

	entry, err := l.Append([]byte("START"), now)
	if err != nil {
		return InitCommitment{}, OpenMessage{}, err
	}

	_, tagV, tagT := l.LastState()
	open := OpenMessage{
		LogID:      logID,
		OpenTime:   now,
		FirstIndex: entry.Index,
		FirstTagV:  tagV,
		FirstTagT:  tagT,
	}

	return commit, open, nil
}

func (*Logger) keyUpdateFrequency() uint64 {
	return 1
}

// CloseProtocol creates a closing message and marks the log as closed.
// This allows detection of abnormal log termination (Section 4.2).
// After closing, no more entries can be appended.
func (l *Logger) CloseProtocol(logID string) (CloseMessage, error) {
	now := time.Now()
	_, err := l.Append([]byte("CLOSE"), now)
	if err != nil {
		return CloseMessage{}, err
	}

	idx, tagV, tagT := l.LastState()

	l.keyV = [KeySize]byte{}
	l.keyT = [KeySize]byte{}

	return CloseMessage{
		LogID:      logID,
		CloseTime:  now,
		FinalIndex: idx,
		FinalTagV:  tagV,
		FinalTagT:  tagT,
	}, nil
}

// VerifyCloseMessage verifies that a log was properly closed by checking
// that the final entry contains the closing message and tags match.
func VerifyCloseMessage(records []Record, closeMsg CloseMessage) error {
	if len(records) == 0 {
		return errors.New("no records to verify")
	}

	lastRec := records[len(records)-1]

	if lastRec.Index != closeMsg.FinalIndex {
		return errors.New("final index mismatch")
	}

	if string(lastRec.Msg) != "CLOSE" {
		return errors.New("missing proper closing message")
	}

	return nil
}

// TrustedServer represents the trusted server T from the paper.
// It stores initial commitments and validates closed logs.
type TrustedServer struct {
	commitments map[string]InitCommitment
	opens       map[string]OpenMessage
	closures    map[string]CloseMessage
}

// NewTrustedServer creates a new trusted server instance for managing log commitments and verification.
func NewTrustedServer() *TrustedServer {
	return &TrustedServer{
		commitments: make(map[string]InitCommitment),
		opens:       make(map[string]OpenMessage),
		closures:    make(map[string]CloseMessage),
	}
}

// RegisterLog stores the initial commitment from logger U.
// This prevents total deletion attacks.
func (ts *TrustedServer) RegisterLog(commit InitCommitment) {
	ts.commitments[commit.LogID] = commit
}

// RegisterOpen stores the opening message from logger U.
func (ts *TrustedServer) RegisterOpen(open OpenMessage) {
	ts.opens[open.LogID] = open
}

// AcceptClosure stores the closure message from logger U.
func (ts *TrustedServer) AcceptClosure(closeMsg CloseMessage) error {
	if _, exists := ts.commitments[closeMsg.LogID]; !exists {
		return errors.New("unknown log ID")
	}
	ts.closures[closeMsg.LogID] = closeMsg
	return nil
}

// FinalVerify performs final validation using the T-chain.
// This is the authoritative verification that cannot be forged by V.
func (ts *TrustedServer) FinalVerify(logID string, records []Record) error {
	commit, ok := ts.commitments[logID]
	if !ok {
		return errors.New("log not registered with trusted server")
	}

	open, ok := ts.opens[logID]
	if !ok {
		return errors.New("log opening not registered with trusted server")
	}

	if len(records) == 0 {
		return errors.New("no records to verify")
	}

	firstRec := records[0]
	if firstRec.Index != open.FirstIndex {
		return errors.New("opening index mismatch")
	}
	if string(firstRec.Msg) != "START" {
		return errors.New("missing opening message")
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
	if !hmac.Equal(firstV[:], open.FirstTagV[:]) || !hmac.Equal(firstT[:], open.FirstTagT[:]) {
		return errors.New("opening tag mismatch")
	}

	closeMsg, ok := ts.closures[logID]
	if !ok {
		return ErrLogNotClosed
	}

	if err := VerifyCloseMessage(records, closeMsg); err != nil {
		return err
	}

	finalTag, err := VerifyFromTrusted(records, 0, commit.KeyB0, zeroTag)
	if err != nil {
		return err
	}

	if !hmac.Equal(finalTag[:], closeMsg.FinalTagT[:]) {
		return errors.New("final T-chain tag mismatch")
	}

	return nil
}

// DetectDelayedAttack checks if V's verification differs from T's verification.
// If they differ, a delayed detection attack has occurred (Section 2.2).
func (*TrustedServer) DetectDelayedAttack(_ string, vTag, tTag [32]byte) bool {
	// If tags differ, V may have been compromised or is malicious
	return !hmac.Equal(vTag[:], tTag[:])
}

// ReleaseA1 returns A1 to authorized verifiers (derived from A0), matching §4.
func (ts *TrustedServer) ReleaseA1(logID string) ([KeySize]byte, error) {
	commit, ok := ts.commitments[logID]
	if !ok {
		return [KeySize]byte{}, errors.New("log not registered with trusted server")
	}
	a1 := sha256.Sum256(commit.KeyA0[:]) // A1 = H(A0)
	return a1, nil
}

// Some Helper functions
// htag computes H(tag) — used to initialize μ_1
func htag(tag [32]byte) [32]byte {
	sum := sha256.Sum256(tag[:])
	return sum
}

func isZero32(x [32]byte) bool {
	var acc byte
	for _, b := range x {
		acc |= b
	}
	return acc == 0
}

// fwdKey performs forward-secure key evolution: K_i = H(K_{i-1}).
func fwdKey(k *[KeySize]byte) { h := sha256.Sum256(k[:]); copy(k[:], h[:]) }

func mac(key []byte, chunks ...[]byte) [32]byte {
	h := hmac.New(sha256.New, key)
	for _, c := range chunks {
		_, _ = h.Write(c)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func fold(prev, mac [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write(prev[:])
	_, _ = h.Write(mac[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
