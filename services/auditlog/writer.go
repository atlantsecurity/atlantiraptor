package auditlog

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// A signed checkpoint is written after this many entries...
	CheckpointEntries = 100
	// ...or this long after the last one when there are new entries.
	CheckpointInterval = 5 * time.Minute

	filePrefix = "audit-"
	fileSuffix = ".jsonl"
	lockName   = ".lock"

	// Longest line read back. Details are capped well below this.
	maxLine = 4 << 20
)

var fileRegex = regexp.MustCompile(`^audit-(\d{4}-\d{2}-\d{2})\.jsonl$`)

// FileName returns the log file name for a UTC day.
func FileName(t time.Time) string {
	return filePrefix + t.UTC().Format("2006-01-02") + fileSuffix
}

// ListFiles returns the log files in a directory, oldest first.
func ListFiles(dir string) ([]string, error) {
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, i := range items {
		if !i.IsDir() && fileRegex.MatchString(i.Name()) {
			out = append(out, i.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// FileDay returns the day (YYYY-MM-DD) of a log file name.
func FileDay(name string) string {
	m := fileRegex.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1]
}

// Head is the newest position of a chain.
type Head struct {
	Seq   uint64 `json:"seq"`
	Hash  string `json:"hash"`
	Time  string `json:"time"`
	KeyId string `json:"key_id"`
}

// Log appends entries to a chain in one directory. Only one process
// may have a directory open (a lock file enforces this).
type Log struct {
	mu sync.Mutex

	dir   string
	key   ed25519.PrivateKey
	keyID string
	now   func() time.Time

	lock    io.Closer
	file    *os.File
	fileDay string

	seq             uint64
	head            string
	headTime        string
	sinceCheckpoint int
	lastCheckpoint  time.Time
	needResume      bool
	closed          bool

	// Called (under the lock, in order) for every line written.
	onWrite func(e *Entry, line []byte)
}

// Options for Open.
type Options struct {
	// Details for the genesis entry of a new chain.
	GenesisDetails map[string]interface{}
	// Called for every line written, in order.
	OnWrite func(e *Entry, line []byte)
	// Clock, for tests.
	Now func() time.Time
}

// Open opens (or starts) the chain in dir.
func Open(dir string, key ed25519.PrivateKey, opts Options) (*Log, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("audit log directory must be an absolute path: %v", dir)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := lockDir(filepath.Join(dir, lockName))
	if err != nil {
		return nil, fmt.Errorf("audit log directory %v is in use by another process: %w", dir, err)
	}
	l := &Log{
		dir:     dir,
		key:     key,
		keyID:   KeyID(key.Public().(ed25519.PublicKey)),
		now:     opts.Now,
		lock:    lock,
		onWrite: opts.OnWrite,
	}
	if l.now == nil {
		l.now = time.Now
	}
	if err := l.resume(opts.GenesisDetails); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return l, nil
}

// Dir returns the log directory.
func (l *Log) Dir() string { return l.dir }

// KeyId returns the fingerprint of the signing key.
func (l *Log) KeyId() string { return l.keyID }

// Head returns the newest position.
func (l *Log) Head() Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Head{Seq: l.seq, Hash: l.head, Time: l.headTime, KeyId: l.keyID}
}

// tail describes the end of the existing chain.
type tail struct {
	last      *Entry
	lastKeyId string
	tornFile  string
	tornLine  []byte
}

// scanTail finds the last valid entry, the key of the newest signed
// entry and a torn (partly written) last line, if any.
func scanTail(dir string) (*tail, error) {
	files, err := ListFiles(dir)
	if err != nil {
		return nil, err
	}
	t := &tail{}
	for i := len(files) - 1; i >= 0; i-- {
		entries, torn, err := readFileEntries(filepath.Join(dir, files[i]))
		if err != nil {
			return nil, err
		}
		if i == len(files)-1 && torn != nil {
			t.tornFile = files[i]
			t.tornLine = torn
		}
		if t.last == nil && len(entries) > 0 {
			t.last = entries[len(entries)-1]
		}
		for j := len(entries) - 1; j >= 0; j-- {
			if entries[j].Signed() {
				t.lastKeyId = entries[j].KeyId
				return t, nil
			}
		}
		if t.last == nil && t.tornLine == nil && i < len(files)-1 {
			// An empty older file; keep looking.
			continue
		}
	}
	return t, nil
}

// readFileEntries parses a file. A last line that does not parse (a
// write cut short by a crash) is returned as torn. A bad line followed
// by a recovery entry is skipped (the verifier checks it); any other
// bad line is an error, since the writer never produces one.
func readFileEntries(path string) ([]*Entry, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var lines [][]byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			lines = append(lines, line)
		}
	}
	var out []*Entry
	for i, line := range lines {
		e := &Entry{}
		if err := json.Unmarshal(line, e); err != nil {
			if i == len(lines)-1 {
				return out, line, nil
			}
			next := &Entry{}
			if json.Unmarshal(lines[i+1], next) == nil && next.Type == TypeRecovered {
				continue
			}
			return nil, nil, fmt.Errorf("%v: entry %d is not a log entry", filepath.Base(path), i+1)
		}
		out = append(out, e)
	}
	return out, nil, nil
}

func (l *Log) resume(genesis map[string]interface{}) error {
	t, err := scanTail(l.dir)
	if err != nil {
		return err
	}
	if t.last == nil {
		l.seq = 0
		l.head = ""
	} else {
		l.seq = t.last.Seq
		l.head = t.last.Hash
		l.headTime = t.last.Time
	}
	l.lastCheckpoint = l.now()

	if t.tornLine != nil {
		if err := l.openFile(t.tornFile); err != nil {
			return err
		}
		// End the torn line so the next entry starts on its own line.
		if _, err := l.file.Write([]byte("\n")); err != nil {
			return err
		}
		sum := sha256.Sum256(t.tornLine)
		if _, err := l.appendLocked(&Entry{
			Type:      TypeRecovered,
			Principal: "AuditLog",
			Operation: "audit_log_recovered",
			Details: mustJSON(map[string]interface{}{
				"torn_bytes":  len(t.tornLine),
				"torn_sha256": hex.EncodeToString(sum[:]),
				"file":        t.tornFile,
			}),
		}); err != nil {
			return err
		}
	}

	switch {
	case t.last == nil && t.tornLine == nil:
		if genesis == nil {
			genesis = map[string]interface{}{}
		}
		if _, err := l.appendLocked(&Entry{
			Type:      TypeGenesis,
			Principal: "AuditLog",
			Operation: "audit_log_created",
			Details:   mustJSON(genesis),
			PublicKey: EncodePublicKey(l.key.Public().(ed25519.PublicKey)),
			KeyId:     l.keyID,
		}); err != nil {
			return err
		}
		l.sinceCheckpoint = 0

	case t.lastKeyId != l.keyID:
		if _, err := l.appendLocked(&Entry{
			Type:      TypeKey,
			Principal: "AuditLog",
			Operation: "audit_log_key_changed",
			Details: mustJSON(map[string]interface{}{
				"previous_key_id": t.lastKeyId,
			}),
			PublicKey: EncodePublicKey(l.key.Public().(ed25519.PublicKey)),
			KeyId:     l.keyID,
		}); err != nil {
			return err
		}
		l.sinceCheckpoint = 0
	}
	l.needResume = false
	return nil
}

func mustJSON(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		data, _ = json.Marshal(map[string]string{"marshal_error": err.Error()})
	}
	return data
}

func (l *Log) openFile(name string) error {
	if l.file != nil && l.file.Name() == filepath.Join(l.dir, name) {
		return nil
	}
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	path := filepath.Join(l.dir, name)
	// A file of an earlier day may have been marked read-only.
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0200 == 0 {
		_ = os.Chmod(path, 0600)
	}
	fd, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	l.file = fd
	l.fileDay = FileDay(name)
	return nil
}

// rotateLocked moves to today's file, ending the previous day's file
// with a checkpoint and marking it read-only.
func (l *Log) rotateLocked(now time.Time) error {
	name := FileName(now)
	day := FileDay(name)
	if l.file != nil && l.fileDay == day {
		return nil
	}
	if l.file != nil {
		prev := l.file.Name()
		if l.sinceCheckpoint > 0 {
			if _, err := l.writeLocked(l.checkpointEntry("day_end"), now); err != nil {
				return err
			}
		}
		_ = l.file.Close()
		l.file = nil
		_ = os.Chmod(prev, 0400)
	}
	return l.openFile(name)
}

func (l *Log) checkpointEntry(reason string) *Entry {
	return &Entry{
		Type:      TypeCheckpoint,
		Principal: "AuditLog",
		Operation: "audit_log_checkpoint",
		Details: mustJSON(map[string]interface{}{
			"reason":  reason,
			"entries": l.sinceCheckpoint,
		}),
		KeyId: l.keyID,
	}
}

// writeLocked seals and writes one entry to the open file.
func (l *Log) writeLocked(e *Entry, now time.Time) (*Entry, error) {
	e.Seq = l.seq + 1
	e.Prev = l.head
	e.Time = now.UTC().Format(time.RFC3339Nano)
	line, err := seal(e, l.key)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		l.needResume = true
		return nil, err
	}
	if err := l.file.Sync(); err != nil {
		l.needResume = true
		return nil, err
	}
	l.seq = e.Seq
	l.head = e.Hash
	l.headTime = e.Time
	if e.Type == TypeCheckpoint || e.Type == TypeGenesis || e.Type == TypeKey {
		l.sinceCheckpoint = 0
		l.lastCheckpoint = now
	} else {
		l.sinceCheckpoint++
	}
	if l.onWrite != nil {
		l.onWrite(e, line[:len(line)-1])
	}
	return e, nil
}

func (l *Log) appendLocked(e *Entry) (*Entry, error) {
	if l.closed {
		return nil, errors.New("audit log is closed")
	}
	now := l.now()
	if err := l.rotateLocked(now); err != nil {
		l.needResume = true
		return nil, err
	}
	out, err := l.writeLocked(e, now)
	if err != nil {
		return nil, err
	}
	if l.sinceCheckpoint >= CheckpointEntries {
		if _, err := l.writeLocked(l.checkpointEntry("count"), now); err != nil {
			return out, err
		}
	}
	return out, nil
}

// Append adds an event to the chain and returns it as written.
func (l *Log) Append(org_id, principal, operation string, details interface{}) (*Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.needResume && !l.closed {
		// A write failed earlier: find out what reached the disk and
		// carry on from there.
		if l.file != nil {
			_ = l.file.Close()
			l.file = nil
		}
		if err := l.resume(nil); err != nil {
			return nil, err
		}
	}
	return l.appendLocked(&Entry{
		Type:      TypeEvent,
		OrgId:     org_id,
		Principal: principal,
		Operation: operation,
		Details:   mustJSON(details),
	})
}

// Checkpoint writes a signed checkpoint if there are entries since the
// last one. With force it writes one anyway.
func (l *Log) Checkpoint(reason string, force bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || (l.sinceCheckpoint == 0 && !force) {
		return nil
	}
	_, err := l.appendLocked(l.checkpointEntry(reason))
	return err
}

// Tick writes a checkpoint when the interval has passed and moves to a
// new file at midnight UTC. Call it regularly.
func (l *Log) Tick() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	now := l.now()
	if err := l.rotateLocked(now); err != nil {
		return err
	}
	if l.sinceCheckpoint > 0 && now.Sub(l.lastCheckpoint) >= CheckpointInterval {
		_, err := l.appendLocked(l.checkpointEntry("interval"))
		return err
	}
	return nil
}

// Close writes a final checkpoint and releases the directory.
func (l *Log) Close(reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	var err error
	if l.sinceCheckpoint > 0 && l.file != nil && !l.needResume {
		_, err = l.appendLocked(l.checkpointEntry(reason))
	}
	l.closed = true
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	_ = l.lock.Close()
	return err
}

// ReadLines calls fn for each raw line of a file, in order.
func ReadLines(path string, fn func(line []byte) error) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()
	scanner := bufio.NewScanner(fd)
	scanner.Buffer(make([]byte, 64<<10), maxLine)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}
