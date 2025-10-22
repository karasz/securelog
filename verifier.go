package securelog

import (
	"crypto/hmac"
	"errors"
)

// SemiTrustedVerifier represents a semi-trusted verifier (V) from Section 4.1 of the paper.
// V can verify logs using the A_i key chain but could potentially modify logs if malicious.
// The T-chain provides protection against malicious verifiers.
type SemiTrustedVerifier struct{ store Store }

// NewSemiTrustedVerifier creates a new semi-trusted verifier that validates the V-chain.
func NewSemiTrustedVerifier(store Store) *SemiTrustedVerifier {
	return &SemiTrustedVerifier{store: store}
}

// VerifyFromAnchor loads records after anchor.Index and verifies the V-chain using (A_i, μ_V,i).
func (v *SemiTrustedVerifier) VerifyFromAnchor(a Anchor) error {
	ch, done, err := v.store.Iter(a.Index + 1)
	if err != nil {
		return err
	}
	defer done()
	var recs []Record
	for r := range ch {
		recs = append(recs, r)
	}
	final, err := VerifyFrom(recs, a.Index, a.Key, a.TagV)
	if err != nil {
		return err
	}
	tail, ok, err := v.store.Tail()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("tail state unavailable")
	}
	if !hmac.Equal(final[:], tail.TagV[:]) {
		return ErrTagMismatch
	}
	return nil
}

// TrustedVerifier represents the trusted server (T) from Section 4.1 of the paper.
// T holds the B_i key chain and can verify the T-chain which is protected from malicious verifiers.
type TrustedVerifier struct {
	store        Store
	initialKeyB0 [KeySize]byte // B_0 - initial key for T-chain
}

// NewTrustedVerifier creates a new trusted verifier that validates the T-chain using initial key B_0.
func NewTrustedVerifier(store Store, b0 [KeySize]byte) *TrustedVerifier {
	return &TrustedVerifier{store: store, initialKeyB0: b0}
}

// VerifyAll verifies the entire log from the beginning using the T-chain.
// This provides final validation that cannot be forged by a malicious verifier V.
func (t *TrustedVerifier) VerifyAll() error {
	ch, done, err := t.store.Iter(1)
	if err != nil {
		return err
	}
	defer done()
	var recs []Record
	for r := range ch {
		recs = append(recs, r)
	}

	var zeroTag [32]byte
	final, err := VerifyFromTrusted(recs, 0, t.initialKeyB0, zeroTag)
	if err != nil {
		return err
	}
	tail, ok, err := t.store.Tail()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("tail state unavailable")
	}
	if !hmac.Equal(final[:], tail.TagT[:]) {
		return ErrTagMismatch
	}
	return nil
}

// VerifyFromAnchor verifies from a checkpoint using the T-chain.
// The anchor must contain B_i and μ_T,i for checkpoint i.
func (t *TrustedVerifier) VerifyFromAnchor(idx uint64, bi [KeySize]byte, tagT [32]byte) error {
	ch, done, err := t.store.Iter(idx + 1)
	if err != nil {
		return err
	}
	defer done()
	var recs []Record
	for r := range ch {
		recs = append(recs, r)
	}
	final, err := VerifyFromTrusted(recs, idx, bi, tagT)
	if err != nil {
		return err
	}
	tail, ok, err := t.store.Tail()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("tail state unavailable")
	}
	if !hmac.Equal(final[:], tail.TagT[:]) {
		return ErrTagMismatch
	}
	return nil
}
