package securelog

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// KeySize is the size in bytes of all cryptographic keys (SHA-256 output size).
const KeySize = 32

// Entry is the authenticated record returned to callers of Append.
type Entry struct {
	Index uint64
	TS    int64 // unix nanos
	Msg   []byte
	Tag   [32]byte // HMAC-SHA256
}

// Record is the persisted form used by Store.
// Contains both MAC chains for dual verification.
type Record struct {
	Index uint64
	TS    int64
	Msg   []byte
	TagV  [32]byte // μ_V,i - semi-trusted verifier chain tag
	TagT  [32]byte // μ_T,i - trusted server chain tag
}

// TailState captures the aggregate MACs μ_V,i and μ_T,i for the current log tail.
type TailState struct {
	Index uint64
	TagV  [32]byte
	TagT  [32]byte
}

// Anchor is the checkpoint tuple shared with verifiers.
type Anchor struct {
	Index uint64
	Key   [KeySize]byte // A_i (verifier key)
	TagV  [32]byte      // μ_V,i
	TagT  [32]byte      // μ_T,i
}

// Config controls logger behavior.
type Config struct {
	AnchorEvery uint64         // publish an anchor every N entries (0=disabled)
	InitialKeyV *[KeySize]byte // optional fixed A0 for verifier chain (for tests/HSMs)
	InitialKeyT *[KeySize]byte // optional fixed B0 for trusted server chain (for tests/HSMs)
}

// Store abstracts persistence & anchor handling.
type Store interface {
	Append(r Record, tail TailState, anchor *Anchor) error
	Iter(startIdx uint64) (<-chan Record, func() error, error)
	AnchorAt(i uint64) (Anchor, bool, error)
	ListAnchors() ([]Anchor, error)
	Tail() (TailState, bool, error)
}

// Logger is the logging server ("U" in the paper).
type Logger struct {
	cfg   Config
	i     uint64
	keyV  [KeySize]byte // A_i - key for semi-trusted verifier chain
	keyT  [KeySize]byte // B_i - key for trusted server chain
	tagV  [32]byte      // μ_V,i (undefined when i==0; first step uses H(tag))
	tagT  [32]byte      // μ_T,i (undefined when i==0; first step uses H(tag))
	store Store
}

// New creates a private‑verifiable logger bound to a Store.
// Initializes both key chains A0 and B0 as per Section 4.2 of the paper.
func New(cfg Config, st Store) (*Logger, error) {
	var a0, b0 [KeySize]byte

	if cfg.InitialKeyV != nil {
		a0 = *cfg.InitialKeyV
	} else {
		if _, err := rand.Read(a0[:]); err != nil {
			return nil, err
		}
	}

	if cfg.InitialKeyT != nil {
		b0 = *cfg.InitialKeyT
	} else {
		if _, err := rand.Read(b0[:]); err != nil {
			return nil, err
		}
	}

	return &Logger{cfg: cfg, keyV: a0, keyT: b0, store: st}, nil
}

// Append logs a message with timestamp, updates state, and persists atomically.
// Implements dual MAC chain computation as per Section 4.2:
// - μ_V,i for semi-trusted verifier V (using key chain A_i)
// - μ_T,i for trusted server T (using key chain B_i)
func (l *Logger) Append(msg []byte, ts time.Time) (Entry, error) {
	l.i++

	fwdKey(&l.keyV)
	fwdKey(&l.keyT)

	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], l.i)
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], uint64(ts.UnixNano()))

	macV := mac(l.keyV[:], idx[:], tsb[:], msg)
	macT := mac(l.keyT[:], idx[:], tsb[:], msg)

	//   First entry after start: μ_1 = H(tag_1)
	//   Subsequent entries:     μ_i = H( μ_{i-1} || tag_i )
	var tagV, tagT [32]byte
	if l.i == 1 && isZero32(l.tagV) && isZero32(l.tagT) {
		tagV = htag(macV)
		tagT = htag(macT)
	} else {
		tagV = fold(l.tagV, macV)
		tagT = fold(l.tagT, macT)
	}

	rec := Record{
		Index: l.i,
		TS:    ts.UnixNano(),
		Msg:   append([]byte(nil), msg...),
		TagV:  tagV,
		TagT:  tagT,
	}

	var anchor *Anchor
	if l.cfg.AnchorEvery != 0 && (l.i%l.cfg.AnchorEvery == 0) {
		cpKey := l.keyV // Store verifier key for checkpoints
		anchor = &Anchor{
			Index: l.i,
			Key:   cpKey,
			TagV:  tagV,
			TagT:  tagT,
		}
	}

	tail := TailState{Index: l.i, TagV: tagV, TagT: tagT}

	if err := l.store.Append(rec, tail, anchor); err != nil {
		l.i--
		return Entry{}, err
	}

	l.tagV = tagV
	l.tagT = tagT

	return Entry{Index: rec.Index, TS: rec.TS, Msg: rec.Msg, Tag: tagV}, nil
}

// Close appends the special CLOSE record per §4 and returns that entry.
func (l *Logger) Close(ts time.Time) (Entry, error) {
	return l.Append([]byte("CLOSE"), ts)
}

// LastState returns current tail state (useful for live checkpoints).
// Returns both μ_V,i and μ_T,i.
func (l *Logger) LastState() (idx uint64, tagV, tagT [32]byte) {
	return l.i, l.tagV, l.tagT
}

// GetInitialKeys returns A0 and B0 for trusted server commitment.
// WARNING: This should only be called during log initialization and
// the keys must be securely transmitted to the trusted server T.
func (l *Logger) GetInitialKeys() (a0, b0 [KeySize]byte) {
	return l.keyV, l.keyT
}
