package securelog

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// fileStore implements Store using POSIX files with append-only semantics.
// File format:
//   - logs.dat: main log file with entries
//   - anchors.idx: anchor index file
//
// Entry format in logs.dat:
//
//	[8]byte: index (uint64)
//	[8]byte: timestamp (int64)
//	[4]byte: msg length (uint32)
//	[n]byte: msg data
//	[32]byte: tagV (μ_V,i)
//	[32]byte: tagT (μ_T,i)
//
// Anchor format in anchors.idx:
//
//	[8]byte: index (uint64)
//	[32]byte: key (A_i)
//	[32]byte: tagV
//	[32]byte: tagT
//
// Tail format in tail.dat:
//
//	[8]byte: index (uint64)
//	[32]byte: tagV
//	[32]byte: tagT
type fileStore struct {
	dir        string
	logFile    *os.File
	anchorFile *os.File
	tailFile   *os.File
	mu         sync.RWMutex
}

const (
	logsFileName    = "logs.dat"
	anchorsFileName = "anchors.idx"
	tailFileName    = "tail.dat"
	headerSize      = 8 + 8 + 4        // idx + ts + msgLen
	tagsSize        = 32 + 32          // tagV + tagT
	anchorEntrySize = 8 + 32 + 32 + 32 // idx + key + tagV + tagT
	tailEntrySize   = 8 + 32 + 32      // idx + tagV + tagT
)

// OpenFileStore creates or opens a POSIX file-based store in the given directory.
func OpenFileStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	logPath := filepath.Join(dir, logsFileName)
	logFile, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	anchorPath := filepath.Join(dir, anchorsFileName)
	anchorFile, err := os.OpenFile(anchorPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("open anchor file: %w", err)
	}

	tailPath := filepath.Join(dir, tailFileName)
	tailFile, err := os.OpenFile(tailPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		_ = logFile.Close()
		_ = anchorFile.Close()
		return nil, fmt.Errorf("open tail file: %w", err)
	}

	return &fileStore{
		dir:        dir,
		logFile:    logFile,
		anchorFile: anchorFile,
		tailFile:   tailFile,
	}, nil
}

// Append writes a record to the log file atomically.
func (s *fileStore) Append(r Record, tail TailState, anchor *Anchor) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lastIdx, err := s.getLastIndexLocked()
	if err != nil {
		return err
	}

	if lastIdx != r.Index-1 {
		return fmt.Errorf("non-contiguous append: have %d, got %d", lastIdx, r.Index)
	}

	if err := syscall.Flock(int(s.logFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock log file: %w", err)
	}
	defer syscall.Flock(int(s.logFile.Fd()), syscall.LOCK_UN)

	if err := s.writeRecordLocked(r); err != nil {
		return err
	}

	if err := s.logFile.Sync(); err != nil {
		return fmt.Errorf("sync log file: %w", err)
	}

	if anchor != nil {
		if err := s.writeAnchorLocked(*anchor); err != nil {
			return err
		}
	}

	return s.writeTailLocked(tail)
}

// writeRecordLocked writes a single record to the log file (caller must hold lock).
func (s *fileStore) writeRecordLocked(r Record) error {
	msgLen := uint32(len(r.Msg))
	totalSize := headerSize + int(msgLen) + tagsSize

	buf := make([]byte, totalSize)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:], r.Index)
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(r.TS))
	offset += 8

	binary.BigEndian.PutUint32(buf[offset:], msgLen)
	offset += 4

	copy(buf[offset:], r.Msg)
	offset += int(msgLen)

	copy(buf[offset:], r.TagV[:])
	offset += 32

	copy(buf[offset:], r.TagT[:])

	n, err := s.logFile.Write(buf)
	if err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	if n != len(buf) {
		return fmt.Errorf("incomplete write: %d of %d bytes", n, len(buf))
	}

	return nil
}

// writeAnchorLocked writes an anchor entry to the anchor file.
func (s *fileStore) writeAnchorLocked(a Anchor) error {
	if err := syscall.Flock(int(s.anchorFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock anchor file: %w", err)
	}
	defer syscall.Flock(int(s.anchorFile.Fd()), syscall.LOCK_UN)

	buf := make([]byte, anchorEntrySize)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:], a.Index)
	offset += 8

	copy(buf[offset:], a.Key[:])
	offset += 32

	copy(buf[offset:], a.TagV[:])
	offset += 32

	copy(buf[offset:], a.TagT[:])

	if _, err := s.anchorFile.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek anchor file: %w", err)
	}

	if _, err := s.anchorFile.Write(buf); err != nil {
		return fmt.Errorf("write anchor: %w", err)
	}

	if err := s.anchorFile.Sync(); err != nil {
		return fmt.Errorf("sync anchor file: %w", err)
	}

	return nil
}

// getLastIndexLocked returns the index of the last record (0 if empty).
func (s *fileStore) getLastIndexLocked() (uint64, error) {
	info, err := s.logFile.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat log file: %w", err)
	}

	if info.Size() == 0 {
		return 0, nil
	}

	// Seek to beginning and read all records to find last index
	// TODO: This is inefficient but simple; could be optimized with index
	if _, err := s.logFile.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek to start: %w", err)
	}

	reader := bufio.NewReader(s.logFile)
	var lastIdx uint64

	for {
		var idxBuf [8]byte
		if _, err := io.ReadFull(reader, idxBuf[:]); err != nil {
			if err == io.EOF {
				break
			}
			return 0, fmt.Errorf("read index: %w", err)
		}
		lastIdx = binary.BigEndian.Uint64(idxBuf[:])

		if _, err := io.CopyN(io.Discard, reader, 8); err != nil {
			return 0, fmt.Errorf("skip timestamp: %w", err)
		}

		var lenBuf [4]byte
		if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
			return 0, fmt.Errorf("read msg length: %w", err)
		}
		msgLen := binary.BigEndian.Uint32(lenBuf[:])

		skipSize := int64(msgLen) + tagsSize
		if _, err := io.CopyN(io.Discard, reader, skipSize); err != nil {
			return 0, fmt.Errorf("skip msg and tags: %w", err)
		}
	}

	return lastIdx, nil
}

// Iter returns a channel that yields records starting from startIdx.
func (s *fileStore) Iter(startIdx uint64) (<-chan Record, func() error, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	logPath := filepath.Join(s.dir, logsFileName)
	file, err := os.Open(logPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file for reading: %w", err)
	}

	out := make(chan Record, 64)
	done := make(chan struct{})

	go func() {
		defer close(out)
		defer file.Close()

		reader := bufio.NewReader(file)

		for {
			select {
			case <-done:
				return
			default:
			}

			var idxBuf [8]byte
			if _, err := io.ReadFull(reader, idxBuf[:]); err != nil {
				if err == io.EOF {
					return
				}
				return // Error reading
			}
			idx := binary.BigEndian.Uint64(idxBuf[:])

			var tsBuf [8]byte
			if _, err := io.ReadFull(reader, tsBuf[:]); err != nil {
				return
			}
			ts := int64(binary.BigEndian.Uint64(tsBuf[:]))

			var lenBuf [4]byte
			if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
				return
			}
			msgLen := binary.BigEndian.Uint32(lenBuf[:])

			msg := make([]byte, msgLen)
			if _, err := io.ReadFull(reader, msg); err != nil {
				return
			}

			var tagV [32]byte
			if _, err := io.ReadFull(reader, tagV[:]); err != nil {
				return
			}

			var tagT [32]byte
			if _, err := io.ReadFull(reader, tagT[:]); err != nil {
				return
			}

			if idx >= startIdx {
				out <- Record{
					Index: idx,
					TS:    ts,
					Msg:   msg,
					TagV:  tagV,
					TagT:  tagT,
				}
			}
		}
	}()

	cleanup := func() error {
		close(done)
		return nil
	}

	return out, cleanup, nil
}

// AnchorAt retrieves the anchor at index i.
func (s *fileStore) AnchorAt(i uint64) (Anchor, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, found, err := s.readAnchorLocked(i)
	return a, found, err
}

// readAnchorLocked searches for an anchor with the given index.
func (s *fileStore) readAnchorLocked(targetIdx uint64) (Anchor, bool, error) {
	var zero Anchor

	if _, err := s.anchorFile.Seek(0, io.SeekStart); err != nil {
		return zero, false, fmt.Errorf("seek anchor file: %w", err)
	}

	reader := bufio.NewReader(s.anchorFile)

	for {
		buf := make([]byte, anchorEntrySize)
		if _, err := io.ReadFull(reader, buf); err != nil {
			if err == io.EOF {
				return zero, false, nil // Not found
			}
			return zero, false, fmt.Errorf("read anchor: %w", err)
		}

		idx := binary.BigEndian.Uint64(buf[0:8])
		if idx == targetIdx {
			var anchor Anchor
			anchor.Index = idx
			copy(anchor.Key[:], buf[8:40])
			copy(anchor.TagV[:], buf[40:72])
			copy(anchor.TagT[:], buf[72:104])
			return anchor, true, nil
		}
	}
}

// ListAnchors returns all anchors in the store.
func (s *fileStore) ListAnchors() ([]Anchor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, err := s.anchorFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek anchor file: %w", err)
	}

	reader := bufio.NewReader(s.anchorFile)
	var anchors []Anchor

	for {
		buf := make([]byte, anchorEntrySize)
		if _, err := io.ReadFull(reader, buf); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read anchor: %w", err)
		}

		idx := binary.BigEndian.Uint64(buf[0:8])
		var anchor Anchor
		anchor.Index = idx
		copy(anchor.Key[:], buf[8:40])
		copy(anchor.TagV[:], buf[40:72])
		copy(anchor.TagT[:], buf[72:104])

		anchors = append(anchors, anchor)
	}

	return anchors, nil
}

// Tail returns the latest tail state (μ_V,i, μ_T,i).
func (s *fileStore) Tail() (TailState, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readTailLocked()
}

func (s *fileStore) readTailLocked() (TailState, bool, error) {
	var tail TailState
	if _, err := s.tailFile.Seek(0, io.SeekStart); err != nil {
		return tail, false, fmt.Errorf("seek tail file: %w", err)
	}
	buf := make([]byte, tailEntrySize)
	if _, err := io.ReadFull(s.tailFile, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return tail, false, nil
		}
		return tail, false, fmt.Errorf("read tail: %w", err)
	}
	tail.Index = binary.BigEndian.Uint64(buf[0:8])
	copy(tail.TagV[:], buf[8:40])
	copy(tail.TagT[:], buf[40:72])
	return tail, true, nil
}

func (s *fileStore) writeTailLocked(tail TailState) error {
	if err := s.tailFile.Truncate(0); err != nil {
		return fmt.Errorf("truncate tail file: %w", err)
	}
	if _, err := s.tailFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek tail file: %w", err)
	}
	buf := make([]byte, tailEntrySize)
	binary.BigEndian.PutUint64(buf[0:8], tail.Index)
	copy(buf[8:40], tail.TagV[:])
	copy(buf[40:72], tail.TagT[:])
	if _, err := s.tailFile.Write(buf); err != nil {
		return fmt.Errorf("write tail: %w", err)
	}
	if err := s.tailFile.Sync(); err != nil {
		return fmt.Errorf("sync tail file: %w", err)
	}
	return nil
}

// Close closes the file store.
func (s *fileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error

	if err := s.logFile.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close log file: %w", err))
	}

	if err := s.anchorFile.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close anchor file: %w", err))
	}

	if err := s.tailFile.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close tail file: %w", err))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}
