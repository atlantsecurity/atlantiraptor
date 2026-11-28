// Package auditlog keeps a tamper-evident copy of the audit log on the
// server's local disk, outside the datastore.
//
// Every audit event becomes one JSON line in a daily file
// (audit-YYYY-MM-DD.jsonl, UTC). Each line carries a sequence number,
// the SHA-256 hash of the previous line and its own hash, so editing,
// inserting, reordering or deleting a line breaks the chain. Every 100
// entries, every five minutes with new entries, on day rollover and at
// shutdown the log writes a checkpoint signed with the server's audit
// key (Ed25519, derived from the server's secrets key, so it survives
// datastore resets and is not stored anywhere). The newest position of
// the chain is also kept in the datastore, so cutting entries off the
// end of the files is noticed too.
//
// The files are never rewritten or deleted by the server. Files of
// past days are marked read-only.
package auditlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Entry types.
const (
	TypeEvent      = "event"
	TypeGenesis    = "genesis"
	TypeCheckpoint = "checkpoint"
	TypeKey        = "key"
	TypeRecovered  = "recovered"
)

// Entry is one line of the log. The JSON field order is fixed by the
// struct and is part of the hash, so do not reorder fields.
type Entry struct {
	Seq       uint64          `json:"seq"`
	Time      string          `json:"time"`
	Type      string          `json:"type"`
	OrgId     string          `json:"org_id,omitempty"`
	Principal string          `json:"principal,omitempty"`
	Operation string          `json:"operation,omitempty"`
	Details   json.RawMessage `json:"details,omitempty"`
	PublicKey string          `json:"public_key,omitempty"`
	KeyId     string          `json:"key_id,omitempty"`
	Prev      string          `json:"prev"`
	Hash      string          `json:"hash,omitempty"`
	Sig       string          `json:"sig,omitempty"`
}

// Signed reports whether this entry type carries a signature.
func (e *Entry) Signed() bool {
	switch e.Type {
	case TypeGenesis, TypeCheckpoint, TypeKey:
		return true
	}
	return false
}

// computeHash returns the hex SHA-256 of the entry without its hash
// and signature.
func computeHash(e *Entry) (string, error) {
	c := *e
	c.Hash = ""
	c.Sig = ""
	data, err := json.Marshal(&c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// seal sets the hash (and signature for signed types) and returns the
// line to write. The entry goes through a JSON round trip first so the
// hash is computed over exactly what a reader will parse back.
func seal(e *Entry, key ed25519.PrivateKey) ([]byte, error) {
	e.Hash = ""
	e.Sig = ""
	if len(e.Details) > 0 {
		var buf bytes.Buffer
		if err := json.Compact(&buf, e.Details); err != nil {
			return nil, err
		}
		e.Details = buf.Bytes()
	}
	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	var round Entry
	if err := json.Unmarshal(data, &round); err != nil {
		return nil, err
	}
	h, err := computeHash(&round)
	if err != nil {
		return nil, err
	}
	round.Hash = h
	if round.Signed() {
		if key == nil {
			return nil, errors.New("audit log: no signing key")
		}
		raw, _ := hex.DecodeString(h)
		round.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))
	}
	*e = round
	return json.Marshal(&round)
}

// verifySig checks the signature of a signed entry against a public key.
func verifySig(e *Entry, pub ed25519.PublicKey) bool {
	raw, err := hex.DecodeString(e.Hash)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil {
		return false
	}
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, raw, sig)
}

// KeyID is a short fingerprint of a public key: the first 16 hex
// characters of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// EncodePublicKey and DecodePublicKey convert keys for the log and the
// command line.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("not an Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// DeriveKey derives the audit signing key from the server's secrets
// key. The same server configuration always gives the same key.
func DeriveKey(secret []byte) ed25519.PrivateKey {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("atlantiraptor audit log signing key v1"))
	return ed25519.NewKeyFromSeed(mac.Sum(nil))
}
