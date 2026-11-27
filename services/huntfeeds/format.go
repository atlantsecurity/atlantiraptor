package huntfeeds

// The feed format. See docs/feeds/README.md for the full description
// that Atlant's feed service implements.
//
// The feed service answers with a Bundle: a JSON manifest (as bytes,
// base64 encoded) and an Ed25519 signature over exactly those bytes,
// made with one of Atlant Security's feed signing keys. The server
// only accepts a manifest whose signature checks out against a public
// key compiled into the binary, that was issued for the licence key
// entered on this server, and whose lease has not run out.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// FormatVersion is the manifest format this server understands.
const FormatVersion = 1

// ArtifactPrefix is required on every artifact a feed delivers, so feed
// content can never replace a built-in or customer artifact.
const ArtifactPrefix = "Atlant.Feed."

const (
	maxBundleSize   = 32 << 20
	maxPacks        = 2000
	maxArtifacts    = 50
	maxClockSkew    = 24 * time.Hour
	maxHuntHours    = 24 * 7
	defaultHuntHour = 24
)

// Bundle is the feed service's response body.
type Bundle struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`   // base64 of the manifest JSON
	Signature string `json:"signature"` // base64 Ed25519 signature over the decoded payload
}

// Manifest is the signed content of a bundle.
type Manifest struct {
	Format int    `json:"format"`
	Feed   string `json:"feed"`
	// When the service issued this manifest.
	Issued time.Time `json:"issued"`
	// The lease: the content may be used until then without hearing
	// from the service again. Never later than Licence.Expires.
	ValidUntil time.Time `json:"valid_until"`
	Licence    Licence   `json:"licence"`
	Packs      []Pack    `json:"packs"`
}

// Licence describes the subscription the manifest was issued for.
type Licence struct {
	ID       string    `json:"id"`
	Customer string    `json:"customer"`
	Plan     string    `json:"plan"`
	Expires  time.Time `json:"expires"`
	// Hex SHA-256 of the licence key: binds the manifest to the key
	// entered on the server.
	KeySHA256 string `json:"key_sha256"`
}

// Pack is one hunt pack: VQL artifacts plus how to hunt with them.
type Pack struct {
	ID          string    `json:"id" yaml:"id"`
	Name        string    `json:"name" yaml:"name"`
	Version     int       `json:"version" yaml:"version"`
	Published   time.Time `json:"published" yaml:"published"`
	Updated     time.Time `json:"updated" yaml:"updated"`
	Severity    string    `json:"severity,omitempty" yaml:"severity"`
	Category    string    `json:"category,omitempty" yaml:"category"`
	Tags        []string  `json:"tags,omitempty" yaml:"tags"`
	Platforms   []string  `json:"platforms,omitempty" yaml:"platforms"`
	Summary     string    `json:"summary,omitempty" yaml:"summary"`
	Description string    `json:"description,omitempty" yaml:"description"`
	References  []string  `json:"references,omitempty" yaml:"references"`
	Changes     string    `json:"changes,omitempty" yaml:"changes"`
	// Artifact definitions (YAML), each named Atlant.Feed.*.
	Artifacts []string `json:"artifacts" yaml:"artifacts"`
	Hunt      HuntSpec `json:"hunt" yaml:"hunt"`
}

// HuntSpec is what the console's "Launch hunt" starts.
type HuntSpec struct {
	Description string `json:"description,omitempty" yaml:"description"`
	// Artifacts to collect; default: every artifact of the pack.
	Artifacts []string `json:"artifacts,omitempty" yaml:"artifacts"`
	// Parameters per artifact: {"Atlant.Feed.X": {"Param": "value"}}.
	Parameters map[string]map[string]string `json:"parameters,omitempty" yaml:"parameters"`
	// "windows", "linux", "darwin" or empty for every client.
	OS string `json:"os,omitempty" yaml:"os"`
	// How long the hunt runs, in hours (1..168, default 24).
	ExpiresHours int `json:"expires_hours,omitempty" yaml:"expires_hours"`
	// Optional CPU limit and timeout passed to the collection.
	CPULimit float32 `json:"cpu_limit,omitempty" yaml:"cpu_limit"`
	Timeout  uint64  `json:"timeout,omitempty" yaml:"timeout"`
}

var (
	packIDRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	artifactNameRe = regexp.MustCompile(`^name:\s*["']?([A-Za-z0-9_.]+)["']?\s*$`)
	validOS        = map[string]bool{"": true, "windows": true, "linux": true, "darwin": true}
	validSeverity  = map[string]bool{"": true, "info": true, "low": true, "medium": true, "high": true, "critical": true}
)

// KeySHA256 is how a licence key is identified in a manifest.
func KeySHA256(licence_key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(licence_key)))
	return hex.EncodeToString(sum[:])
}

// ParseBundle decodes a bundle and checks its signature against keys
// (key id -> Ed25519 public key). It returns the manifest bytes and
// the decoded manifest. It does not check the licence or the lease.
func ParseBundle(data []byte, keys map[string]ed25519.PublicKey) (*Manifest, error) {
	if len(keys) == 0 {
		return nil, errNoKeys
	}
	if len(data) > maxBundleSize {
		return nil, errors.New("feed bundle is too large")
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("feed bundle is not valid JSON: %w", err)
	}
	pub, ok := keys[b.KeyID]
	if !ok {
		return nil, fmt.Errorf("feed bundle is signed with unknown key %q", b.KeyID)
	}
	payload, err := base64.StdEncoding.DecodeString(b.Payload)
	if err != nil {
		return nil, errors.New("feed bundle payload is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("feed bundle signature is malformed")
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, errors.New("feed bundle signature does not verify")
	}
	m := &Manifest{}
	if err := json.Unmarshal(payload, m); err != nil {
		return nil, fmt.Errorf("feed manifest is not valid JSON: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// SignManifest makes a bundle. It is used by the "feeds sign" command
// and by tests; the feed service can do the same in any language.
func SignManifest(m *Manifest, key_id string, priv ed25519.PrivateKey) ([]byte, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	b := Bundle{
		KeyID:     key_id,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}
	return json.MarshalIndent(b, "", " ")
}

// CheckFor checks that the manifest belongs to licence_key and may be
// used at now.
func (self *Manifest) CheckFor(licence_key string, now time.Time) error {
	if !strings.EqualFold(self.Licence.KeySHA256, KeySHA256(licence_key)) {
		return errors.New("the feed was issued for a different licence key")
	}
	if self.Issued.After(now.Add(maxClockSkew)) {
		return fmt.Errorf("the feed is dated %v, in the future: check the server clock",
			self.Issued.UTC().Format(time.RFC3339))
	}
	if !now.Before(self.Licence.Expires) {
		return errExpired
	}
	if !now.Before(self.ValidUntil) {
		return errLeaseOver
	}
	return nil
}

// UsableUntil is when the content stops being usable without a new
// manifest from the service.
func (self *Manifest) UsableUntil() time.Time {
	if self.Licence.Expires.Before(self.ValidUntil) {
		return self.Licence.Expires
	}
	return self.ValidUntil
}

func (self *Manifest) validate() error {
	if self.Format != FormatVersion {
		return fmt.Errorf("feed format %d is not supported by this server (expected %d): update Atlantiraptor",
			self.Format, FormatVersion)
	}
	if self.Issued.IsZero() || self.ValidUntil.IsZero() || self.Licence.Expires.IsZero() {
		return errors.New("feed manifest is missing its dates")
	}
	if !self.ValidUntil.After(self.Issued) {
		return errors.New("feed manifest lease ends before it was issued")
	}
	if len(self.Licence.KeySHA256) != 64 {
		return errors.New("feed manifest is not bound to a licence key")
	}
	if len(self.Packs) > maxPacks {
		return errors.New("feed manifest has too many packs")
	}
	seen_packs := map[string]bool{}
	seen_artifacts := map[string]string{}
	for i := range self.Packs {
		p := &self.Packs[i]
		if err := p.normalize(); err != nil {
			return fmt.Errorf("pack %q: %w", p.ID, err)
		}
		if seen_packs[p.ID] {
			return fmt.Errorf("pack %q appears twice", p.ID)
		}
		seen_packs[p.ID] = true
		for _, name := range p.ArtifactNames() {
			if other, ok := seen_artifacts[name]; ok {
				return fmt.Errorf("artifact %v is in packs %q and %q", name, other, p.ID)
			}
			seen_artifacts[name] = p.ID
		}
	}
	return nil
}

// normalize checks a pack and fills in hunt defaults.
func (self *Pack) normalize() error {
	if !packIDRe.MatchString(self.ID) {
		return errors.New("the id must be 2-64 lowercase letters, digits, '.', '_' or '-'")
	}
	if strings.TrimSpace(self.Name) == "" {
		return errors.New("the pack has no name")
	}
	if self.Version < 1 {
		return errors.New("the version must be 1 or more")
	}
	self.Severity = strings.ToLower(self.Severity)
	if !validSeverity[self.Severity] {
		return fmt.Errorf("unknown severity %q", self.Severity)
	}
	if len(self.Artifacts) == 0 || len(self.Artifacts) > maxArtifacts {
		return fmt.Errorf("a pack needs 1 to %d artifacts", maxArtifacts)
	}
	names := map[string]bool{}
	for _, def := range self.Artifacts {
		name := artifactName(def)
		if !strings.HasPrefix(name, ArtifactPrefix) || len(name) <= len(ArtifactPrefix) {
			return fmt.Errorf("artifact %q must be named %v*", name, ArtifactPrefix)
		}
		if names[name] {
			return fmt.Errorf("artifact %v appears twice", name)
		}
		names[name] = true
	}
	h := &self.Hunt
	if len(h.Artifacts) == 0 {
		h.Artifacts = self.ArtifactNames()
	}
	for _, a := range h.Artifacts {
		if !names[a] {
			return fmt.Errorf("the hunt collects %v, which is not in the pack", a)
		}
	}
	for a := range h.Parameters {
		if !names[a] {
			return fmt.Errorf("hunt parameters for %v, which is not in the pack", a)
		}
	}
	h.OS = strings.ToLower(h.OS)
	if !validOS[h.OS] {
		return fmt.Errorf("unknown hunt os %q", h.OS)
	}
	if h.ExpiresHours <= 0 {
		h.ExpiresHours = defaultHuntHour
	}
	if h.ExpiresHours > maxHuntHours {
		h.ExpiresHours = maxHuntHours
	}
	if h.CPULimit < 0 || h.CPULimit > 100 {
		h.CPULimit = 0
	}
	if self.Updated.IsZero() {
		self.Updated = self.Published
	}
	return nil
}

// ArtifactNames lists the names of the pack's artifacts, in order.
func (self *Pack) ArtifactNames() []string {
	res := make([]string, 0, len(self.Artifacts))
	for _, def := range self.Artifacts {
		res = append(res, artifactName(def))
	}
	return res
}

// artifactName finds the top level "name:" of an artifact definition
// without a full parse (the repository parses and validates it later).
func artifactName(def string) string {
	for _, line := range strings.Split(def, "\n") {
		line = strings.TrimRight(line, "\r")
		if m := artifactNameRe.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

var (
	errNoKeys    = errors.New("this build has no feed signing key, so it cannot use hunt feeds")
	errExpired   = errors.New("the subscription has expired")
	errLeaseOver = errors.New("the feed could not be renewed in time")
)

// Verify checks a bundle against the keys compiled into this binary.
func Verify(data []byte) (*Manifest, error) {
	return ParseBundle(data, publicKeys())
}
