package auditlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }

func testKey(seed byte) ed25519.PrivateKey {
	return DeriveKey(bytes.Repeat([]byte{seed}, 32))
}

func newLog(t *testing.T, dir string, key ed25519.PrivateKey, c *clock) *Log {
	l, err := Open(dir, key, Options{Now: c.Now,
		GenesisDetails: map[string]interface{}{"directory": dir}})
	require.NoError(t, err)
	return l
}

func writeEvents(t *testing.T, l *Log, c *clock, n int) {
	for i := 0; i < n; i++ {
		c.t = c.t.Add(time.Second)
		_, err := l.Append("root", "alice", "CreateHunt",
			map[string]interface{}{"hunt_id": i, "html": "<b>&</b>"})
		require.NoError(t, err)
	}
}

func verify(t *testing.T, dir string, opts VerifyOptions) *Result {
	r, err := Verify(dir, opts)
	require.NoError(t, err)
	return r
}

func messages(r *Result) string {
	var out []string
	for _, p := range r.Problems {
		out = append(out, p.Severity+": "+p.Message)
	}
	return strings.Join(out, "\n")
}

func readLines(t *testing.T, path string) []string {
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	_ = os.Chmod(path, 0600)
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600))
}

func start() *clock {
	return &clock{t: time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)}
}

func TestChainVerifies(t *testing.T) {
	dir := t.TempDir()
	c := start()
	key := testKey(1)
	l := newLog(t, dir, key, c)
	writeEvents(t, l, c, 250)
	head := l.Head()
	require.NoError(t, l.Close("shutdown"))

	r := verify(t, dir, VerifyOptions{
		TrustedKeys: []ed25519.PublicKey{key.Public().(ed25519.PublicKey)},
		Anchor:      &head,
	})
	assert.True(t, r.Ok, messages(r))
	assert.Equal(t, 0, r.Warnings, messages(r))
	// genesis + 250 events + checkpoints at 100, 200 and shutdown.
	assert.Equal(t, uint64(254), r.Entries)
	assert.Equal(t, 3, r.Checkpoints)
	assert.Equal(t, uint64(0), r.UnsignedTail)

	// Reopening continues the same chain.
	l = newLog(t, dir, key, c)
	writeEvents(t, l, c, 3)
	require.NoError(t, l.Close("shutdown"))
	r = verify(t, dir, VerifyOptions{})
	assert.True(t, r.Ok, messages(r))
	assert.Equal(t, uint64(258), r.LastSeq)
	assert.Equal(t, []string{KeyID(key.Public().(ed25519.PublicKey))}, r.KeyIds)
}

func TestTamperingIsDetected(t *testing.T) {
	setup := func(t *testing.T) (string, string, Head, ed25519.PrivateKey) {
		dir := t.TempDir()
		c := start()
		key := testKey(1)
		l := newLog(t, dir, key, c)
		writeEvents(t, l, c, 20)
		head := l.Head()
		require.NoError(t, l.Close("shutdown"))
		return dir, filepath.Join(dir, FileName(c.t)), head, key
	}

	t.Run("edited entry", func(t *testing.T) {
		dir, path, _, _ := setup(t)
		lines := readLines(t, path)
		lines[5] = strings.Replace(lines[5], `"alice"`, `"mallory"`, 1)
		writeLines(t, path, lines)
		r := verify(t, dir, VerifyOptions{})
		assert.False(t, r.Ok)
		assert.Contains(t, messages(r), "Entry 6 was changed")
	})

	t.Run("edited entry with recomputed hash", func(t *testing.T) {
		dir, path, _, _ := setup(t)
		lines := readLines(t, path)
		e := &Entry{}
		require.NoError(t, json.Unmarshal([]byte(lines[5]), e))
		e.Principal = "mallory"
		data, err := seal(e, nil)
		require.NoError(t, err)
		lines[5] = string(data)
		writeLines(t, path, lines)
		r := verify(t, dir, VerifyOptions{})
		assert.False(t, r.Ok)
		assert.Contains(t, messages(r), "Entry 7 does not follow entry 6")
	})

	t.Run("deleted entry", func(t *testing.T) {
		dir, path, _, _ := setup(t)
		lines := readLines(t, path)
		lines = append(lines[:8], lines[9:]...)
		writeLines(t, path, lines)
		r := verify(t, dir, VerifyOptions{})
		assert.False(t, r.Ok)
		assert.Contains(t, messages(r), "Entries 9 to 9 are missing")
	})

	t.Run("reordered entries", func(t *testing.T) {
		dir, path, _, _ := setup(t)
		lines := readLines(t, path)
		lines[3], lines[4] = lines[4], lines[3]
		writeLines(t, path, lines)
		r := verify(t, dir, VerifyOptions{})
		assert.False(t, r.Ok)
	})

	t.Run("truncated tail", func(t *testing.T) {
		dir, path, head, _ := setup(t)
		lines := readLines(t, path)
		writeLines(t, path, lines[:15])
		// The chain itself is consistent...
		r := verify(t, dir, VerifyOptions{})
		assert.True(t, r.Ok, messages(r))
		assert.NotZero(t, r.UnsignedTail)
		// ...but the server's recorded position shows the cut.
		r = verify(t, dir, VerifyOptions{Anchor: &head})
		assert.False(t, r.Ok)
		assert.Contains(t, messages(r), "removed from the end")
	})

	t.Run("deleted beginning", func(t *testing.T) {
		dir, path, _, _ := setup(t)
		lines := readLines(t, path)
		writeLines(t, path, lines[3:])
		r := verify(t, dir, VerifyOptions{})
		assert.False(t, r.Ok)
		assert.Contains(t, messages(r), "The log starts at entry 4")
	})

	t.Run("garbage line", func(t *testing.T) {
		dir, path, _, _ := setup(t)
		lines := readLines(t, path)
		lines = append(lines[:4], append([]string{"hello"}, lines[4:]...)...)
		writeLines(t, path, lines)
		r := verify(t, dir, VerifyOptions{})
		assert.False(t, r.Ok)
	})

	t.Run("rewritten with another key", func(t *testing.T) {
		dir, path, head, key := setup(t)
		// An attacker rebuilds the whole chain with their own key.
		lines := readLines(t, path)
		other := testKey(9)
		var prev string
		for i, line := range lines {
			e := &Entry{}
			require.NoError(t, json.Unmarshal([]byte(line), e))
			e.Prev = prev
			if e.Type == TypeGenesis {
				e.PublicKey = EncodePublicKey(other.Public().(ed25519.PublicKey))
			}
			if e.Signed() {
				e.KeyId = KeyID(other.Public().(ed25519.PublicKey))
			}
			if e.Seq == 6 {
				e.Principal = "mallory"
			}
			data, err := seal(e, other)
			require.NoError(t, err)
			lines[i] = string(data)
			prev = e.Hash
		}
		writeLines(t, path, lines)
		r := verify(t, dir, VerifyOptions{})
		assert.True(t, r.Ok, "a self-consistent forgery passes without a trusted key")
		r = verify(t, dir, VerifyOptions{
			TrustedKeys: []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}, Anchor: &head})
		assert.False(t, r.Ok)
		assert.Contains(t, messages(r), "not this server's audit key")
		assert.Contains(t, messages(r), "the log was rewritten")
	})

	t.Run("forged checkpoint signature", func(t *testing.T) {
		dir, path, _, _ := setup(t)
		lines := readLines(t, path)
		last := len(lines) - 1
		e := &Entry{}
		require.NoError(t, json.Unmarshal([]byte(lines[last]), e))
		require.Equal(t, TypeCheckpoint, e.Type)
		e.Sig = strings.Repeat("A", len(e.Sig)-2) + "=="
		data, _ := json.Marshal(e)
		lines[last] = string(data)
		writeLines(t, path, lines)
		r := verify(t, dir, VerifyOptions{})
		assert.False(t, r.Ok)
		assert.Contains(t, messages(r), "signature of checkpoint")
	})
}

func TestRotationAndCheckpoints(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t: time.Date(2026, 11, 28, 23, 50, 0, 0, time.UTC)}
	key := testKey(1)
	l := newLog(t, dir, key, c)
	writeEvents(t, l, c, 3)

	// Interval checkpoint.
	c.t = c.t.Add(CheckpointInterval)
	require.NoError(t, l.Tick())
	assert.Equal(t, 0, l.sinceCheckpoint)

	writeEvents(t, l, c, 2)
	c.t = time.Date(2026, 11, 29, 0, 0, 30, 0, time.UTC)
	writeEvents(t, l, c, 2)
	require.NoError(t, l.Close("shutdown"))

	files, err := ListFiles(dir)
	require.NoError(t, err)
	assert.Equal(t, []string{"audit-2026-11-28.jsonl", "audit-2026-11-29.jsonl"}, files)

	// The previous day's file ends with a checkpoint and is read-only.
	lines := readLines(t, filepath.Join(dir, files[0]))
	assert.Contains(t, lines[len(lines)-1], `"reason":"day_end"`)
	st, err := os.Stat(filepath.Join(dir, files[0]))
	require.NoError(t, err)
	assert.Zero(t, st.Mode().Perm()&0200)

	r := verify(t, dir, VerifyOptions{})
	assert.True(t, r.Ok, messages(r))
	assert.Equal(t, 0, r.Warnings, messages(r))

	// Deleting a whole day is detected.
	_ = os.Chmod(filepath.Join(dir, files[0]), 0600)
	require.NoError(t, os.Remove(filepath.Join(dir, files[0])))
	r = verify(t, dir, VerifyOptions{})
	assert.False(t, r.Ok)
}

func TestTornWriteRecovery(t *testing.T) {
	dir := t.TempDir()
	c := start()
	key := testKey(1)
	l := newLog(t, dir, key, c)
	writeEvents(t, l, c, 5)
	require.NoError(t, l.Close("shutdown"))

	// Simulate a crash in the middle of a write.
	path := filepath.Join(dir, FileName(c.t))
	fd, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, _ = fd.Write([]byte(`{"seq":8,"time":"2026-11-28T10:00`))
	fd.Close()

	r := verify(t, dir, VerifyOptions{})
	assert.True(t, r.Ok, messages(r))
	assert.Equal(t, 1, r.Warnings)

	l = newLog(t, dir, key, c)
	writeEvents(t, l, c, 2)
	require.NoError(t, l.Close("shutdown"))

	r = verify(t, dir, VerifyOptions{})
	assert.True(t, r.Ok, messages(r))
	assert.Equal(t, 0, r.Warnings, messages(r))
}

func TestKeyChange(t *testing.T) {
	dir := t.TempDir()
	c := start()
	l := newLog(t, dir, testKey(1), c)
	writeEvents(t, l, c, 2)
	require.NoError(t, l.Close("shutdown"))

	l = newLog(t, dir, testKey(2), c)
	writeEvents(t, l, c, 2)
	require.NoError(t, l.Close("shutdown"))

	r := verify(t, dir, VerifyOptions{
		TrustedKeys: []ed25519.PublicKey{testKey(2).Public().(ed25519.PublicKey)}})
	assert.True(t, r.Ok, messages(r))
	assert.Equal(t, 1, r.Warnings)
	assert.Contains(t, messages(r), "signing key changed")
	assert.Len(t, r.KeyIds, 2)
}

func TestLockedDirectory(t *testing.T) {
	dir := t.TempDir()
	c := start()
	l := newLog(t, dir, testKey(1), c)
	defer l.Close("shutdown")
	_, err := Open(dir, testKey(1), Options{Now: c.Now})
	assert.Error(t, err)
}

func TestQueryAndExport(t *testing.T) {
	dir := t.TempDir()
	c := start()
	l := newLog(t, dir, testKey(1), c)
	writeEvents(t, l, c, 5)
	_, err := l.Append("O123", "bob", "Login", map[string]string{"remote": "10.1.1.1"})
	require.NoError(t, err)
	require.NoError(t, l.Close("shutdown"))

	rows, more, err := Query(dir, Filter{Limit: 3})
	require.NoError(t, err)
	assert.True(t, more)
	assert.Len(t, rows, 3)
	assert.Equal(t, "Login", rows[0].Operation)

	rows, _, err = Query(dir, Filter{Principal: "ALI"})
	require.NoError(t, err)
	assert.Len(t, rows, 5)

	rows, _, err = Query(dir, Filter{Search: "10.1.1.1"})
	require.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, "O123", rows[0].OrgId)

	rows, _, err = Query(dir, Filter{Checkpoints: true, Limit: 1000})
	require.NoError(t, err)
	assert.Len(t, rows, 8)

	rows, _, err = Query(dir, Filter{BeforeSeq: 4})
	require.NoError(t, err)
	assert.Len(t, rows, 2)

	var n int
	require.NoError(t, Export(dir, Filter{Checkpoints: true}, func(line []byte, e *Entry) error {
		n++
		return nil
	}))
	assert.Equal(t, 8, n)
}
