package securelog

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// ErrGap indicates missing or non-sequential log entries were detected during verification.
var ErrGap = errors.New("gap or reordering detected")

// ErrTagMismatch indicates a MAC tag verification failure, suggesting tampering or incorrect keys.
var ErrTagMismatch = errors.New("tag mismatch: tampering or wrong key")

// VerifyChain verifies either the V-chain or T-chain depending on useVerifierChain.
func VerifyChain(
	records []Record, startIdx uint64, kStart [KeySize]byte,
	tStart [32]byte, useVerifierChain bool,
) (lastTag [32]byte, err error) {
	key := kStart
	prev := tStart
	expect := startIdx

	for _, r := range records {
		expect++
		if r.Index != expect {
			return lastTag, ErrGap
		}

		h := sha256.Sum256(key[:])
		copy(key[:], h[:])

		var idx [8]byte
		binary.BigEndian.PutUint64(idx[:], r.Index)
		var tsb [8]byte
		binary.BigEndian.PutUint64(tsb[:], uint64(r.TS))

		macVal := mac(key[:], idx[:], tsb[:], r.Msg)
		//   if starting from zero aggregate (full replay), use μ = H(tag) for the first step
		//   else (from an anchor), μ = H(μ_prev || tag)
		var tag [32]byte
		if isZero32(prev) {
			tag = htag(macVal)
		} else {
			tag = fold(prev, macVal)
		}

		var stored [32]byte
		if useVerifierChain {
			stored = r.TagV
		} else {
			stored = r.TagT
		}

		if !constantTimeEqual(tag[:], stored[:]) {
			return lastTag, ErrTagMismatch
		}

		prev = tag
		lastTag = tag
	}
	return lastTag, nil
}

// constantTimeEqual performs constant-time comparison of two byte slices.
// This prevents timing attacks that could reveal information about the tags.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// VerifyFrom checks records using the V-chain (for semi-trusted verifier).
// This is backward compatible with the original single-chain implementation.
func VerifyFrom(
	records []Record, startIdx uint64, kStart [KeySize]byte, tStart [32]byte,
) (lastTag [32]byte, err error) {
	return VerifyChain(records, startIdx, kStart, tStart, true)
}

// VerifyFromTrusted checks records using the T-chain (for trusted server T).
func VerifyFromTrusted(
	records []Record, startIdx uint64, kStart [KeySize]byte, tStart [32]byte,
) (lastTag [32]byte, err error) {
	return VerifyChain(records, startIdx, kStart, tStart, false)
}
