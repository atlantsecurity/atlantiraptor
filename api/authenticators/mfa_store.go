package authenticators

// Two-factor authentication records for password (basic auth) logins.
//
// Each user's record is a small JSON file in the root org file store
// next to the user's other data. A missing record means the user has
// not enrolled a second factor and logs in exactly as before; a record
// that exists but cannot be read is treated as "deny" so a storage
// problem never silently drops the second factor.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	"www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/paths"
	"www.velocidex.com/golang/velociraptor/utils"
)

const mfaCacheTTL = 10 * time.Second

type MFARecord struct {
	// Enrolled TOTP secret (base32). Empty when TOTP is not enabled.
	TOTPSecret string `json:"totp_secret,omitempty"`
	// Secret generated during enrolment, enabled once a code is confirmed.
	PendingTOTPSecret string `json:"pending_totp_secret,omitempty"`
	// Last accepted TOTP time step, to reject replayed codes.
	TOTPLastStep int64 `json:"totp_last_step,omitempty"`
	// SHA-256 hashes of unused recovery codes.
	RecoveryHashes []string `json:"recovery_hashes,omitempty"`
	// Bumped whenever factors change or the password changes; every
	// 2FA session cookie carries it, so a bump revokes all sessions.
	Generation int64 `json:"generation"`
	Updated    int64 `json:"updated"`
}

func (self *MFARecord) Enrolled() bool {
	return self != nil && self.TOTPSecret != ""
}

type mfaCacheEntry struct {
	record  *MFARecord
	fetched time.Time
}

var (
	mfaMu    sync.Mutex
	mfaCache = map[string]mfaCacheEntry{}
)

func mfaPath(username string) api.FSPathSpec {
	return paths.USERS_ROOT.AddChild(username, "atl_mfa").
		AsFilestorePath().SetType(api.PATH_TYPE_FILESTORE_JSON)
}

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || os.IsNotExist(err)
}

// LoadMFA returns the user's record, nil when the user never enrolled,
// or an error when the record exists but cannot be read.
func LoadMFA(root_config *config_proto.Config, username string) (*MFARecord, error) {
	key := utils.ToLower(username)

	mfaMu.Lock()
	entry, ok := mfaCache[key]
	mfaMu.Unlock()
	if ok && time.Since(entry.fetched) < mfaCacheTTL {
		return entry.record, nil
	}

	// Read and cache under the same lock as updates, so an older read
	// can never overwrite a newer record in the cache.
	updateMu.Lock()
	defer updateMu.Unlock()

	record, err := readMFA(root_config, username)
	if err != nil {
		return nil, err
	}

	mfaMu.Lock()
	mfaCache[key] = mfaCacheEntry{record: record, fetched: time.Now()}
	mfaMu.Unlock()
	return record, nil
}

func readMFA(root_config *config_proto.Config, username string) (*MFARecord, error) {
	fs := file_store.GetFileStore(root_config)
	if fs == nil {
		return nil, errors.New("file store unavailable")
	}
	pathspec := mfaPath(username)

	_, err := fs.StatFile(pathspec)
	if err != nil {
		if isNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat two-factor record: %w", err)
	}

	reader, err := fs.ReadFile(pathspec)
	if err != nil {
		return nil, fmt.Errorf("open two-factor record: %w", err)
	}
	defer reader.Close()

	data, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read two-factor record: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	record := &MFARecord{}
	if err := json.Unmarshal(data, record); err != nil {
		return nil, fmt.Errorf("parse two-factor record: %w", err)
	}
	return record, nil
}

// UpdateMFA reads the current record, applies change and writes it back
// under a process-wide lock.
func UpdateMFA(root_config *config_proto.Config, username string,
	change func(r *MFARecord) error) (*MFARecord, error) {

	updateMu.Lock()
	defer updateMu.Unlock()

	record, err := readMFA(root_config, username)
	if err != nil {
		return nil, err
	}
	if record == nil {
		record = &MFARecord{}
	}
	if err := change(record); err != nil {
		return nil, err
	}
	record.Updated = time.Now().Unix()

	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode two-factor record: %w", err)
	}

	fs := file_store.GetFileStore(root_config)
	writer, err := fs.WriteFile(mfaPath(username))
	if err != nil {
		return nil, fmt.Errorf("open two-factor record for writing: %w", err)
	}
	if err := writer.Truncate(); err != nil {
		writer.Close()
		return nil, fmt.Errorf("truncate two-factor record: %w", err)
	}
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return nil, fmt.Errorf("write two-factor record: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close two-factor record: %w", err)
	}

	mfaMu.Lock()
	mfaCache[utils.ToLower(username)] = mfaCacheEntry{record: record, fetched: time.Now()}
	mfaMu.Unlock()
	return record, nil
}

var updateMu sync.Mutex

// RevokeMFASessions invalidates all 2FA session cookies for a user, for
// example after a password change. Users without a record are left alone.
func RevokeMFASessions(root_config *config_proto.Config, username string) error {
	existing, err := readMFA(root_config, username)
	if err != nil || existing == nil {
		return err
	}
	_, err = UpdateMFA(root_config, username, func(r *MFARecord) error {
		r.Generation++
		return nil
	})
	return err
}
