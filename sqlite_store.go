package securelog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // Import SQLite driver for database/sql
)

type sqliteStore struct{ db *sql.DB }

// OpenSQLiteStore opens/creates a SQLite DB and ensures schema + PRAGMAs.
func OpenSQLiteStore(dsn string) (Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	st := &sqliteStore{db: db}
	for _, p := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=FULL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA wal_autocheckpoint=1000;",
	} {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("set %s: %w", p, err)
		}
	}
	schema := `
CREATE TABLE IF NOT EXISTS logs (
  idx   INTEGER PRIMARY KEY,
  ts    INTEGER NOT NULL,
  msg   BLOB    NOT NULL,
  tagV  BLOB    NOT NULL,      -- μ_V,i (semi-trusted verifier chain tag)
  tagT  BLOB    NOT NULL       -- μ_T,i (trusted server chain tag)
);
CREATE TABLE IF NOT EXISTS tail (
  id    INTEGER PRIMARY KEY CHECK(id=1),
  idx   INTEGER NOT NULL,
  tagV  BLOB    NOT NULL,
  tagT  BLOB    NOT NULL
);
CREATE TABLE IF NOT EXISTS anchors (
  idx   INTEGER PRIMARY KEY,
  key   BLOB NOT NULL,      -- A_i (verifier key at checkpoint i)
  tagV  BLOB NOT NULL,      -- μ_V,i at checkpoint i
  tagT  BLOB NOT NULL       -- μ_T,i at checkpoint i
);
CREATE UNIQUE INDEX IF NOT EXISTS anchors_idx_uq ON anchors(idx);
`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return st, nil
}

// Append stores a record, updates tail state, and optionally stores an anchor checkpoint.
func (s *sqliteStore) Append(r Record, tail TailState, anchor *Anchor) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var maxIdx sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(idx),0) FROM logs`).Scan(&maxIdx.Int64); err != nil {
		return err
	}
	if uint64(maxIdx.Int64) != r.Index-1 {
		return fmt.Errorf("non-contiguous append: have %d, got %d", maxIdx.Int64, r.Index)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO logs(idx, ts, msg, tagV, tagT) VALUES(?, ?, ?, ?, ?)`,
		r.Index, r.TS, r.Msg, r.TagV[:], r.TagT[:]); err != nil {
		return err
	}

	if anchor != nil {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO anchors(idx, key, tagV, tagT) VALUES(?, ?, ?, ?)
			 ON CONFLICT(idx) DO UPDATE SET key=excluded.key, tagV=excluded.tagV, tagT=excluded.tagT`,
			anchor.Index, anchor.Key[:], anchor.TagV[:], anchor.TagT[:]); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO tail(id, idx, tagV, tagT) VALUES(1, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET idx=excluded.idx, tagV=excluded.tagV, tagT=excluded.tagT`,
		tail.Index, tail.TagV[:], tail.TagT[:]); err != nil {
		return err
	}

	return tx.Commit()
}

// Iter returns a channel that streams records starting from startIdx in ascending order.
func (s *sqliteStore) Iter(startIdx uint64) (<-chan Record, func() error, error) {
	ctx, cancel := context.WithCancel(context.Background())
	query := `SELECT idx, ts, msg, tagV, tagT FROM logs WHERE idx >= ? ORDER BY idx ASC`
	rows, err := s.db.QueryContext(ctx, query, startIdx)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	out := make(chan Record, 64)
	go func() {
		defer close(out)
		defer rows.Close()
		defer cancel()
		for rows.Next() {
			var idx uint64
			var ts int64
			var msg, tagVBytes, tagTBytes []byte
			if err := rows.Scan(&idx, &ts, &msg, &tagVBytes, &tagTBytes); err != nil {
				return
			}
			var tagV, tagT [32]byte
			copy(tagV[:], tagVBytes)
			copy(tagT[:], tagTBytes)
			out <- Record{Index: idx, TS: ts, Msg: msg, TagV: tagV, TagT: tagT}
		}
	}()
	return out, func() error { cancel(); return nil }, nil
}

// AnchorAt retrieves the anchor checkpoint at the specified index.
func (s *sqliteStore) AnchorAt(i uint64) (Anchor, bool, error) {
	var zero Anchor
	var idx int64
	var key, tagV, tagT []byte
	err := s.db.QueryRow(`SELECT idx, key, tagV, tagT FROM anchors WHERE idx=?`, i).Scan(&idx, &key, &tagV, &tagT)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	if len(key) != KeySize || len(tagV) != 32 || len(tagT) != 32 {
		return zero, false, fmt.Errorf("invalid anchor sizes")
	}
	var out Anchor
	out.Index = uint64(idx)
	copy(out.Key[:], key)
	copy(out.TagV[:], tagV)
	copy(out.TagT[:], tagT)
	return out, true, nil
}

// ListAnchors returns all stored anchor checkpoints in ascending order by index.
func (s *sqliteStore) ListAnchors() ([]Anchor, error) {
	rows, err := s.db.Query(`SELECT idx, key, tagV, tagT FROM anchors ORDER BY idx ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Anchor
	for rows.Next() {
		var idx uint64
		var keyB, tagVB, tagTB []byte
		if err := rows.Scan(&idx, &keyB, &tagVB, &tagTB); err != nil {
			return nil, err
		}
		if len(keyB) != KeySize || len(tagVB) != 32 || len(tagTB) != 32 {
			continue
		}
		var k [KeySize]byte
		var tv, tt [32]byte
		copy(k[:], keyB)
		copy(tv[:], tagVB)
		copy(tt[:], tagTB)
		out = append(out, Anchor{Index: idx, Key: k, TagV: tv, TagT: tt})
	}
	return out, nil
}

// Tail returns the current tail state containing the latest index and MAC tags.
func (s *sqliteStore) Tail() (TailState, bool, error) {
	var tail TailState
	var idx int64
	var tagV, tagT []byte
	err := s.db.QueryRow(`SELECT idx, tagV, tagT FROM tail WHERE id=1`).Scan(&idx, &tagV, &tagT)
	if errors.Is(err, sql.ErrNoRows) {
		return tail, false, nil
	}
	if err != nil {
		return tail, false, err
	}
	if len(tagV) != 32 || len(tagT) != 32 {
		return tail, false, fmt.Errorf("invalid tail sizes")
	}
	tail.Index = uint64(idx)
	copy(tail.TagV[:], tagV)
	copy(tail.TagT[:], tagT)
	return tail, true, nil
}
