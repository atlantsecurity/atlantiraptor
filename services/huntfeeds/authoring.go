package huntfeeds

// Helpers for Atlant's side: generating a signing key, loading pack
// files and signing a feed for one customer. Used by the hidden
// "feeds" command; the feed service can use the command or do the
// same in its own language (see docs/feeds/README.md).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Velocidex/yaml/v2"
	artifacts_proto "www.velocidex.com/golang/velociraptor/artifacts/proto"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/services/repository"
)

// SigningKey is the file written by "feeds keygen". Keep it secret.
type SigningKey struct {
	KeyID      string `json:"key_id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func GenerateSigningKey(key_id string) (*SigningKey, error) {
	if !packIDRe.MatchString(key_id) {
		return nil, errors.New("the key id must be 2-64 lowercase letters, digits, '.', '_' or '-'")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SigningKey{
		KeyID:      key_id,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}, nil
}

func ReadSigningKey(path string) (string, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var k SigningKey
	if err := json.Unmarshal(data, &k); err != nil {
		return "", nil, fmt.Errorf("%v is not a feed signing key: %w", path, err)
	}
	raw, err := base64.StdEncoding.DecodeString(k.PrivateKey)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return "", nil, fmt.Errorf("%v has no valid private key", path)
	}
	return k.KeyID, ed25519.PrivateKey(raw), nil
}

// LoadPacks reads every *.yaml / *.yml pack file in dir.
func LoadPacks(dir string) ([]Pack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var packs []Pack
	for _, e := range entries {
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if e.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var p Pack
		if err := yaml.UnmarshalStrict(data, &p); err != nil {
			return nil, fmt.Errorf("%v: %w", name, err)
		}
		if err := p.normalize(); err != nil {
			return nil, fmt.Errorf("%v: %w", name, err)
		}
		packs = append(packs, p)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	return packs, nil
}

// IssueOptions describe one customer's subscription.
type IssueOptions struct {
	Feed       string
	LicenceKey string
	LicenceID  string
	Customer   string
	Plan       string
	Expires    time.Time
	Lease      time.Duration
	Now        time.Time
}

// BuildManifest makes the manifest for one customer. The lease never
// runs past the end of the subscription.
func BuildManifest(packs []Pack, o IssueOptions) (*Manifest, error) {
	if strings.TrimSpace(o.LicenceKey) == "" {
		return nil, errors.New("a licence key is required")
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Lease <= 0 {
		o.Lease = 14 * 24 * time.Hour
	}
	if !o.Expires.After(o.Now) {
		return nil, errors.New("the subscription has already expired")
	}
	valid := o.Now.Add(o.Lease)
	if valid.After(o.Expires) {
		valid = o.Expires
	}
	if o.Feed == "" {
		o.Feed = "atlant-premium"
	}
	m := &Manifest{
		Format:     FormatVersion,
		Feed:       o.Feed,
		Issued:     o.Now.UTC().Truncate(time.Second),
		ValidUntil: valid.UTC().Truncate(time.Second),
		Licence: Licence{
			ID: o.LicenceID, Customer: o.Customer, Plan: o.Plan,
			Expires:   o.Expires.UTC(),
			KeySHA256: KeySHA256(o.LicenceKey),
		},
		Packs: packs,
	}
	if m.Packs == nil {
		m.Packs = []Pack{}
	}
	return m, m.validate()
}

// CheckPackArtifacts parses and validates every artifact of the packs
// (VQL syntax, parameters, client type) the way a server does when it
// installs them.
func CheckPackArtifacts(packs []Pack) error {
	for _, p := range packs {
		repo := &repository.Repository{Data: map[string]*artifacts_proto.Artifact{}}
		for _, def := range p.Artifacts {
			art, err := repo.LoadYaml(def, services.ArtifactOptions{ValidateArtifact: true})
			if err != nil {
				return fmt.Errorf("pack %v: %w", p.ID, err)
			}
			if art.Type != "client" {
				return fmt.Errorf("pack %v: artifact %v is of type %v; feeds only deliver client artifacts",
					p.ID, art.Name, art.Type)
			}
		}
	}
	return nil
}
