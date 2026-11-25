package api

// API keys for SIEM/SOAR integration.
//
// Each key acts as its own principal ("api-<id>") with the roles chosen
// when it was created, set as a normal ACL policy in one org. Every
// request made with the key is therefore checked by the same permission
// code as console users: a key with the hunter role is refused response
// artifacts exactly like a hunter user. Keys can't be given
// administrator, org_admin or artifact_writer.
//
// The secret is shown once at creation. Only an HMAC of it is stored,
// keyed with a value derived from the server key.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	acl_proto "www.velocidex.com/golang/velociraptor/acls/proto"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	fs_api "www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/path_specs"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	apiKeyPrefix      = "atl_"
	maxAPIKeys        = 200
	defaultKeyRate    = 5  // requests per second
	defaultKeyBurst   = 30 // burst size
	lastUsedWriteGap  = 60 * time.Second
	apiKeyCacheTTL    = 10 * time.Second
	apiPrincipalLabel = "api-"
)

// Roles an API key may hold. Server-wide powers are left out on purpose.
var apiKeyRoles = []string{"reader", "analyst", "investigator", "hunter", "responder", "api"}

var apiKeyNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}$`)

type APIKey struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Hash      string   `json:"hash,omitempty"`
	Hint      string   `json:"hint"`
	Roles     []string `json:"roles"`
	OrgId     string   `json:"org_id"`
	CreatedBy string   `json:"created_by"`
	Created   int64    `json:"created"`
	Expires   int64    `json:"expires,omitempty"`
	LastUsed  int64    `json:"last_used,omitempty"`
	RateLimit int      `json:"rate_limit,omitempty"`
}

func (k APIKey) Principal() string { return apiPrincipalLabel + k.ID }

// Public view without the hash.
func (k APIKey) Public() APIKey {
	k.Hash = ""
	return k
}

type apiKeyDoc struct {
	Keys []APIKey `json:"keys"`
}

var (
	apiKeyMu      sync.Mutex
	apiKeyCache   *apiKeyDoc
	apiKeyFetched time.Time
	lastUsedSaved = map[string]time.Time{}
)

func apiKeysPath() fs_api.FSPathSpec {
	return path_specs.NewSafeFilestorePath("config", "atl_api_keys").
		SetType(fs_api.PATH_TYPE_FILESTORE_JSON)
}

func apiKeyPepper(root *config_proto.Config) ([]byte, error) {
	if root == nil || root.Frontend == nil || root.Frontend.PrivateKey == "" {
		return nil, errors.New("server key unavailable")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("atlantiraptor-apikey-v1\x00"))
	_, _ = h.Write([]byte(root.Frontend.PrivateKey))
	return h.Sum(nil), nil
}

func hashSecret(pepper []byte, secret string) string {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// readKeysLocked reads the key document. Caller holds apiKeyMu.
func readKeysLocked(root *config_proto.Config) (*apiKeyDoc, error) {
	if apiKeyCache != nil && time.Since(apiKeyFetched) < apiKeyCacheTTL {
		return apiKeyCache, nil
	}
	fs := file_store.GetFileStore(root)
	if fs == nil {
		return nil, errors.New("file store unavailable")
	}
	doc := &apiKeyDoc{}
	if _, err := fs.StatFile(apiKeysPath()); err != nil {
		if !errors.Is(err, os.ErrNotExist) && !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat api keys: %w", err)
		}
	} else {
		reader, err := fs.ReadFile(apiKeysPath())
		if err != nil {
			return nil, fmt.Errorf("open api keys: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(reader, 4<<20))
		reader.Close()
		if err != nil {
			return nil, fmt.Errorf("read api keys: %w", err)
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, doc); err != nil {
				return nil, fmt.Errorf("parse api keys: %w", err)
			}
		}
	}
	apiKeyCache, apiKeyFetched = doc, time.Now()
	return doc, nil
}

func writeKeysLocked(root *config_proto.Config, doc *apiKeyDoc) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	fs := file_store.GetFileStore(root)
	writer, err := fs.WriteFile(apiKeysPath())
	if err != nil {
		return fmt.Errorf("open api keys for writing: %w", err)
	}
	if err := writer.Truncate(); err != nil {
		writer.Close()
		return err
	}
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	apiKeyCache, apiKeyFetched = doc, time.Now()
	return nil
}

func ListAPIKeys(root *config_proto.Config) ([]APIKey, error) {
	apiKeyMu.Lock()
	defer apiKeyMu.Unlock()
	doc, err := readKeysLocked(root)
	if err != nil {
		return nil, err
	}
	out := make([]APIKey, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		out = append(out, k.Public())
	}
	return out, nil
}

func validateKeyRoles(roles []string) ([]string, error) {
	out := []string{}
	for _, r := range roles {
		if !utils.InString(apiKeyRoles, r) {
			return nil, fmt.Errorf("role %q can't be given to an API key", r)
		}
		if !utils.InString(out, r) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("pick at least one role")
	}
	return out, nil
}

// CreateAPIKey stores a new key, grants its roles in the org and returns
// the key record and the full token (shown once).
func CreateAPIKey(root, org_config *config_proto.Config, creator, name string,
	roles []string, ttl time.Duration) (APIKey, string, error) {

	if !apiKeyNameRe.MatchString(name) {
		return APIKey{}, "", errors.New("name: 1-64 letters, digits, spaces, dots, dashes or underscores")
	}
	roles, err := validateKeyRoles(roles)
	if err != nil {
		return APIKey{}, "", err
	}
	pepper, err := apiKeyPepper(root)
	if err != nil {
		return APIKey{}, "", err
	}

	idBytes := make([]byte, 8)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return APIKey{}, "", err
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return APIKey{}, "", err
	}
	id := hex.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	now := time.Now()
	key := APIKey{
		ID: id, Name: name, Hash: hashSecret(pepper, secret), Hint: secret[:4],
		Roles: roles, OrgId: org_config.OrgId, CreatedBy: creator, Created: now.Unix(),
		RateLimit: defaultKeyRate,
	}
	if ttl > 0 {
		key.Expires = now.Add(ttl).Unix()
	}

	apiKeyMu.Lock()
	defer apiKeyMu.Unlock()
	doc, err := readKeysLocked(root)
	if err != nil {
		return APIKey{}, "", err
	}
	if len(doc.Keys) >= maxAPIKeys {
		return APIKey{}, "", fmt.Errorf("at most %d API keys", maxAPIKeys)
	}

	// Grant the roles to the key's principal in its org.
	if err := services.SetPolicy(org_config, key.Principal(), &acl_proto.ApiClientACL{Roles: roles}); err != nil {
		return APIKey{}, "", fmt.Errorf("grant key roles: %w", err)
	}
	next := &apiKeyDoc{Keys: append(append([]APIKey{}, doc.Keys...), key)}
	if err := writeKeysLocked(root, next); err != nil {
		_ = services.SetPolicy(org_config, key.Principal(), &acl_proto.ApiClientACL{})
		return APIKey{}, "", err
	}
	return key.Public(), apiKeyPrefix + id + "_" + secret, nil
}

// RevokeAPIKey removes a key and its permissions.
func RevokeAPIKey(root *config_proto.Config, id string) (APIKey, error) {
	apiKeyMu.Lock()
	defer apiKeyMu.Unlock()
	doc, err := readKeysLocked(root)
	if err != nil {
		return APIKey{}, err
	}
	var found *APIKey
	kept := []APIKey{}
	for i := range doc.Keys {
		if doc.Keys[i].ID == id {
			k := doc.Keys[i]
			found = &k
			continue
		}
		kept = append(kept, doc.Keys[i])
	}
	if found == nil {
		return APIKey{}, errors.New("no such key")
	}
	// Remove the key's permissions first; if that fails the key stays
	// listed so the revoke can be retried.
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return APIKey{}, err
	}
	if org_config, err := org_manager.GetOrgConfig(found.OrgId); err == nil {
		if err := services.SetPolicy(org_config, found.Principal(), &acl_proto.ApiClientACL{}); err != nil {
			return APIKey{}, fmt.Errorf("remove key permissions: %w", err)
		}
	}
	if err := writeKeysLocked(root, &apiKeyDoc{Keys: kept}); err != nil {
		return APIKey{}, err
	}
	return found.Public(), nil
}

var errBadToken = errors.New("invalid or expired API key")

// VerifyAPIKey checks a bearer token and returns the key.
func VerifyAPIKey(root *config_proto.Config, token string, now time.Time) (APIKey, error) {
	if !strings.HasPrefix(token, apiKeyPrefix) || len(token) > 200 {
		return APIKey{}, errBadToken
	}
	rest := token[len(apiKeyPrefix):]
	sep := strings.IndexByte(rest, '_')
	if sep != 16 {
		return APIKey{}, errBadToken
	}
	id, secret := rest[:sep], rest[sep+1:]
	pepper, err := apiKeyPepper(root)
	if err != nil {
		return APIKey{}, errBadToken
	}

	apiKeyMu.Lock()
	defer apiKeyMu.Unlock()
	doc, err := readKeysLocked(root)
	if err != nil {
		return APIKey{}, err
	}
	for i := range doc.Keys {
		k := &doc.Keys[i]
		if k.ID != id {
			continue
		}
		if !hmac.Equal([]byte(k.Hash), []byte(hashSecret(pepper, secret))) {
			return APIKey{}, errBadToken
		}
		if k.Expires > 0 && now.Unix() >= k.Expires {
			return APIKey{}, errBadToken
		}
		// Record last use, at most once a minute per key.
		if now.Sub(lastUsedSaved[k.ID]) > lastUsedWriteGap {
			lastUsedSaved[k.ID] = now
			updated := &apiKeyDoc{Keys: append([]APIKey{}, doc.Keys...)}
			updated.Keys[i].LastUsed = now.Unix()
			_ = writeKeysLocked(root, updated)
			return updated.Keys[i], nil
		}
		return *k, nil
	}
	return APIKey{}, errBadToken
}

// Token bucket rate limiter per key.
type bucket struct {
	tokens float64
	last   time.Time
}

var (
	bucketMu sync.Mutex
	buckets  = map[string]*bucket{}
)

func allowRequest(k APIKey, now time.Time) bool {
	rate := float64(k.RateLimit)
	if rate <= 0 {
		rate = defaultKeyRate
	}
	burst := float64(defaultKeyBurst)
	bucketMu.Lock()
	defer bucketMu.Unlock()
	b := buckets[k.ID]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		buckets[k.ID] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Failed authentication is limited per remote address: 20 failures, then
// one more every 3 seconds.
const (
	authFailBurst = 20
	authFailRate  = 1.0 / 3
)

const maxAuthFailEntries = 10000

var (
	authFailMu       sync.Mutex
	authFails        = map[string]*bucket{}
	authFailOverflow = &bucket{tokens: authFailBurst}
	lastAuthPrune    time.Time
)

func refillShared(b *bucket, now time.Time) *bucket {
	if b.last.IsZero() {
		b.last = now
	}
	b.tokens += now.Sub(b.last).Seconds() * authFailRate
	if b.tokens > authFailBurst {
		b.tokens = authFailBurst
	}
	b.last = now
	return b
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func refillAuth(ip string, now time.Time) *bucket {
	b := authFails[ip]
	if b == nil {
		if len(authFails) >= maxAuthFailEntries {
			// Prune at most every 10 seconds; while the table is full,
			// unknown addresses share one bucket, so the cap holds.
			if now.Sub(lastAuthPrune) > 10*time.Second {
				lastAuthPrune = now
				pruneAuthFails(now)
			}
			if len(authFails) >= maxAuthFailEntries {
				return refillShared(authFailOverflow, now)
			}
		}
		b = &bucket{tokens: authFailBurst, last: now}
		authFails[ip] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * authFailRate
	if b.tokens > authFailBurst {
		b.tokens = authFailBurst
	}
	b.last = now
	return b
}

// pruneAuthFails drops addresses that have fully recovered, then the
// oldest entries if the table is still full. Blocked addresses stay.
func pruneAuthFails(now time.Time) {
	for ip, b := range authFails {
		if b.tokens+now.Sub(b.last).Seconds()*authFailRate >= authFailBurst {
			delete(authFails, ip)
		}
	}
	// Still full: drop the entries idle longest (beyond ten minutes).
	for ip, b := range authFails {
		if len(authFails) < maxAuthFailEntries {
			break
		}
		if now.Sub(b.last) > 10*time.Minute {
			delete(authFails, ip)
		}
	}
}

func authBlocked(ip string, now time.Time) bool {
	authFailMu.Lock()
	defer authFailMu.Unlock()
	return refillAuth(ip, now).tokens < 1
}

func authFailed(ip string, now time.Time) {
	authFailMu.Lock()
	defer authFailMu.Unlock()
	refillAuth(ip, now).tokens--
}
