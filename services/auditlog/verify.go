package auditlog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Problem is one finding of a verification.
type Problem struct {
	Severity string `json:"severity"` // error or warning
	File     string `json:"file,omitempty"`
	Seq      uint64 `json:"seq,omitempty"`
	Message  string `json:"message"`
}

// VerifyOptions add checks against what the server knows.
type VerifyOptions struct {
	// The chain's current key must be one of these (if any are given).
	TrustedKeys []ed25519.PublicKey
	// The newest position the server recorded in its datastore. The
	// chain must reach it, with the same hash.
	Anchor *Head
	// Stop after this entry (0: read to the end). Used while the log is
	// being written, so a line being appended is not mistaken for a
	// torn one.
	UpTo uint64
}

var errStop = errors.New("stop")

// Result of a verification.
type Result struct {
	Ok                 bool      `json:"ok"`
	Directory          string    `json:"directory"`
	Files              int       `json:"files"`
	Entries            uint64    `json:"entries"`
	FirstTime          string    `json:"first_time,omitempty"`
	LastTime           string    `json:"last_time,omitempty"`
	LastSeq            uint64    `json:"last_seq"`
	Head               string    `json:"head,omitempty"`
	Checkpoints        int       `json:"checkpoints"`
	LastCheckpointSeq  uint64    `json:"last_checkpoint_seq"`
	LastCheckpointTime string    `json:"last_checkpoint_time,omitempty"`
	UnsignedTail       uint64    `json:"unsigned_tail"`
	KeyIds             []string  `json:"key_ids"`
	Errors             int       `json:"errors"`
	Warnings           int       `json:"warnings"`
	Problems           []Problem `json:"problems"`
	Checked            int64     `json:"checked"`
	DurationMs         int64     `json:"duration_ms"`
}

const maxProblems = 200

func (r *Result) add(sev, file string, seq uint64, format string, args ...interface{}) {
	if sev == "error" {
		r.Errors++
	} else {
		r.Warnings++
	}
	if len(r.Problems) < maxProblems {
		r.Problems = append(r.Problems, Problem{
			Severity: sev, File: file, Seq: seq, Message: fmt.Sprintf(format, args...)})
	}
}

// Verify checks the whole chain in dir.
func Verify(dir string, opts VerifyOptions) (*Result, error) {
	start := time.Now()
	r := &Result{Directory: dir, KeyIds: []string{}, Problems: []Problem{}}
	files, err := ListFiles(dir)
	if err != nil {
		return nil, err
	}
	r.Files = len(files)

	var (
		prev       *Entry
		curKey     ed25519.PublicKey
		tornSum    string
		tornFile   string
		anchorSeen bool
		lastTime   time.Time
	)

	done := false
	for _, name := range files {
		if done {
			break
		}
		day := FileDay(name)
		err := ReadLines(filepath.Join(dir, name), func(line []byte) error {
			if done {
				return errStop
			}
			e := &Entry{}
			if err := json.Unmarshal(line, e); err != nil {
				if tornSum != "" {
					r.add("error", tornFile, 0, "A line that is not a log entry: the file was edited.")
				}
				sum := sha256.Sum256(line)
				tornSum = hex.EncodeToString(sum[:])
				tornFile = name
				return nil
			}

			if tornSum != "" {
				ok := false
				if e.Type == TypeRecovered {
					var d struct {
						Sum string `json:"torn_sha256"`
					}
					_ = json.Unmarshal(e.Details, &d)
					ok = d.Sum == tornSum
				}
				if !ok {
					r.add("error", tornFile, e.Seq, "A line that is not a log entry: the file was edited.")
				}
				tornSum = ""
			}

			r.Entries++
			h, err := computeHash(e)
			if err != nil || h != e.Hash {
				r.add("error", name, e.Seq, "Entry %d was changed after it was written (its hash does not match).", e.Seq)
			}

			if prev == nil {
				if e.Seq != 1 || e.Type != TypeGenesis {
					r.add("error", name, e.Seq, "The log starts at entry %d: earlier entries, or whole files, are missing.", e.Seq)
				}
				if e.Prev != "" && e.Seq == 1 {
					r.add("error", name, e.Seq, "The first entry does not start a chain.")
				}
				r.FirstTime = e.Time
			} else {
				switch {
				case e.Seq == prev.Seq+1:
				case e.Seq <= prev.Seq:
					r.add("error", name, e.Seq, "Entry %d appears after entry %d: entries were reordered or duplicated.", e.Seq, prev.Seq)
				default:
					r.add("error", name, e.Seq, "Entries %d to %d are missing.", prev.Seq+1, e.Seq-1)
				}
				if e.Prev != prev.Hash {
					r.add("error", name, e.Seq, "Entry %d does not follow entry %d (the chain is broken there).", e.Seq, prev.Seq)
				}
			}

			switch e.Type {
			case TypeGenesis, TypeKey:
				if e.Type == TypeGenesis && prev != nil {
					r.add("error", name, e.Seq, "A second chain starts at entry %d.", e.Seq)
				}
				pub, err := DecodePublicKey(e.PublicKey)
				if err != nil {
					r.add("error", name, e.Seq, "Entry %d has an invalid public key.", e.Seq)
					break
				}
				if e.Type == TypeKey {
					r.add("warning", name, e.Seq,
						"The signing key changed at entry %d (to %v). Expected only if the server configuration was replaced.",
						e.Seq, KeyID(pub))
				}
				curKey = pub
				r.KeyIds = append(r.KeyIds, KeyID(pub))
				if KeyID(pub) != e.KeyId || !verifySig(e, pub) {
					r.add("error", name, e.Seq, "The signature of entry %d is not valid.", e.Seq)
				}
			case TypeCheckpoint:
				r.Checkpoints++
				if curKey == nil || e.KeyId != KeyID(curKey) || !verifySig(e, curKey) {
					r.add("error", name, e.Seq, "The signature of checkpoint %d is not valid.", e.Seq)
				} else {
					r.LastCheckpointSeq = e.Seq
					r.LastCheckpointTime = e.Time
				}
			case TypeEvent, TypeRecovered:
			default:
				r.add("error", name, e.Seq, "Entry %d has an unknown type %q.", e.Seq, e.Type)
			}
			if e.Type == TypeGenesis || e.Type == TypeKey {
				r.LastCheckpointSeq = e.Seq
				r.LastCheckpointTime = e.Time
			}

			if t, err := time.Parse(time.RFC3339Nano, e.Time); err != nil {
				r.add("error", name, e.Seq, "Entry %d has no valid time.", e.Seq)
			} else {
				if day != "" && t.UTC().Format("2006-01-02") != day && e.Type == TypeEvent {
					r.add("warning", name, e.Seq, "Entry %d (%v) is in the file of another day.", e.Seq, e.Time)
				}
				if !lastTime.IsZero() && t.Before(lastTime.Add(-time.Minute)) {
					r.add("warning", name, e.Seq, "The time goes back at entry %d (was the clock changed?).", e.Seq)
				}
				lastTime = t
			}

			if opts.Anchor != nil && e.Seq == opts.Anchor.Seq {
				anchorSeen = true
				if e.Hash != opts.Anchor.Hash {
					r.add("error", name, e.Seq,
						"Entry %d differs from the one the server recorded: the log was rewritten.", e.Seq)
				}
			}
			prev = e
			if opts.UpTo > 0 && e.Seq >= opts.UpTo {
				done = true
			}
			return nil
		})
		if err != nil && err != errStop {
			r.add("error", name, 0, "Could not read the file: %v", err)
		}
	}

	if tornSum != "" {
		r.add("warning", tornFile, 0,
			"The last line was cut short (the server stopped while writing). The server records this when it starts.")
	}
	if prev == nil {
		r.add("error", "", 0, "The log has no entries.")
	} else {
		r.LastSeq = prev.Seq
		r.Head = prev.Hash
		r.LastTime = prev.Time
		r.UnsignedTail = prev.Seq - r.LastCheckpointSeq
	}

	if len(opts.TrustedKeys) > 0 && curKey != nil {
		trusted := false
		for _, k := range opts.TrustedKeys {
			if KeyID(k) == KeyID(curKey) {
				trusted = true
			}
		}
		if !trusted {
			r.add("error", "", 0, "The log is signed with key %v, which is not this server's audit key.", KeyID(curKey))
		}
	}
	if opts.Anchor != nil && opts.Anchor.Seq > 0 && !anchorSeen {
		r.add("error", "", opts.Anchor.Seq,
			"The server recorded entry %d (%v), but the log ends at entry %d: entries were removed from the end.",
			opts.Anchor.Seq, opts.Anchor.Time, r.LastSeq)
	}

	r.Ok = r.Errors == 0
	r.Checked = time.Now().Unix()
	r.DurationMs = time.Since(start).Milliseconds()
	return r, nil
}

// Filter selects entries for browsing and export.
type Filter struct {
	From, To    time.Time
	Principal   string
	Operation   string
	OrgId       string
	Search      string
	Checkpoints bool // include checkpoints and other log bookkeeping
	Limit       int
	BeforeSeq   uint64 // for paging: only entries older than this
}

func containsFold(s, sub string) bool {
	return sub == "" || strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func (f *Filter) match(e *Entry, line []byte) bool {
	if !f.Checkpoints && e.Type != TypeEvent {
		return false
	}
	if f.BeforeSeq > 0 && e.Seq >= f.BeforeSeq {
		return false
	}
	if f.OrgId != "" && e.OrgId != f.OrgId {
		return false
	}
	if !containsFold(e.Principal, f.Principal) || !containsFold(e.Operation, f.Operation) {
		return false
	}
	if f.Search != "" && !containsFold(string(line), f.Search) {
		return false
	}
	if !f.From.IsZero() || !f.To.IsZero() {
		t, err := time.Parse(time.RFC3339Nano, e.Time)
		if err != nil {
			return false
		}
		if !f.From.IsZero() && t.Before(f.From) {
			return false
		}
		if !f.To.IsZero() && t.After(f.To) {
			return false
		}
	}
	return true
}

// filesInRange returns the files that can hold entries in the range.
func filesInRange(dir string, from, to time.Time) ([]string, error) {
	files, err := ListFiles(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range files {
		day := FileDay(f)
		if !from.IsZero() && day < from.UTC().Format("2006-01-02") {
			continue
		}
		if !to.IsZero() && day > to.UTC().Format("2006-01-02") {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// Query returns matching entries, newest first, and whether there are
// more.
func Query(dir string, f Filter) ([]*Entry, bool, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	files, err := filesInRange(dir, f.From, f.To)
	if err != nil {
		return nil, false, err
	}
	var out []*Entry
	for i := len(files) - 1; i >= 0; i-- {
		var matched []*Entry
		err := ReadLines(filepath.Join(dir, files[i]), func(line []byte) error {
			e := &Entry{}
			if json.Unmarshal(line, e) != nil {
				return nil
			}
			if f.match(e, line) {
				matched = append(matched, e)
			}
			return nil
		})
		if err != nil {
			return nil, false, err
		}
		for j := len(matched) - 1; j >= 0; j-- {
			if len(out) == f.Limit {
				return out, true, nil
			}
			out = append(out, matched[j])
		}
	}
	return out, false, nil
}

// Export calls fn with each matching raw line and entry, oldest first.
// Limit is ignored.
func Export(dir string, f Filter, fn func(line []byte, e *Entry) error) error {
	files, err := filesInRange(dir, f.From, f.To)
	if err != nil {
		return err
	}
	for _, name := range files {
		err := ReadLines(filepath.Join(dir, name), func(line []byte) error {
			e := &Entry{}
			if json.Unmarshal(line, e) != nil {
				return nil
			}
			if !f.match(e, line) {
				return nil
			}
			return fn(line, e)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
