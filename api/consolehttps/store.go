package consolehttps

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/acme/autocert"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	"www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/path_specs"
	"www.velocidex.com/golang/velociraptor/services/secrets"
)

// What is kept on disk: the confirmed settings and, in certificate
// mode, the private key encrypted with the server's secrets key.
type stored struct {
	Settings Settings `json:"settings"`
	KeyEnc   []byte   `json:"key_enc,omitempty"`
}

func settingsPath() api.FSPathSpec {
	return path_specs.NewSafeFilestorePath("config", "atl_console_https").
		SetType(api.PATH_TYPE_FILESTORE_JSON)
}

func acmePath(key string) api.FSPathSpec {
	return path_specs.NewSafeFilestorePath("config", "atl_acme", key).
		SetType(api.PATH_TYPE_FILESTORE_JSON)
}

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || os.IsNotExist(err)
}

func readFile(config_obj *config_proto.Config, p api.FSPathSpec) ([]byte, error) {
	fs := file_store.GetFileStore(config_obj)
	if fs == nil {
		return nil, errors.New("file store unavailable")
	}
	if _, err := fs.StatFile(p); err != nil {
		return nil, err
	}
	reader, err := fs.ReadFile(p)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, 4<<20))
}

func writeFile(config_obj *config_proto.Config, p api.FSPathSpec, data []byte) error {
	fs := file_store.GetFileStore(config_obj)
	if fs == nil {
		return errors.New("file store unavailable")
	}
	writer, err := fs.WriteFile(p)
	if err != nil {
		return err
	}
	if err := writer.Truncate(); err != nil {
		writer.Close()
		return err
	}
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return err
	}
	return writer.Close()
}

// load returns the confirmed settings and decrypted key, or a disabled
// setting when nothing was saved.
func load(ctx context.Context, config_obj *config_proto.Config) (Settings, []byte, error) {
	data, err := readFile(config_obj, settingsPath())
	if err != nil {
		if isNotExist(err) {
			return Settings{}, nil, nil
		}
		return Settings{}, nil, err
	}
	if len(data) == 0 {
		return Settings{}, nil, nil
	}
	var s stored
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{}, nil, err
	}
	var key []byte
	if len(s.KeyEnc) > 0 {
		key, err = secrets.DecryptBlob(ctx, config_obj, s.KeyEnc)
		if err != nil {
			return s.Settings, nil, fmt.Errorf("the saved private key could not be decrypted: %w", err)
		}
	}
	return s.Settings, key, nil
}

func save(ctx context.Context, config_obj *config_proto.Config, st Settings, key []byte) error {
	s := stored{Settings: st}
	if st.Enabled && st.Mode == ModeCertificate && len(key) > 0 {
		enc, err := secrets.EncryptBlob(ctx, config_obj, key)
		if err != nil {
			return err
		}
		s.KeyEnc = enc
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeFile(config_obj, settingsPath(), data)
}

// acmeCache keeps Let's Encrypt account and certificate keys in the
// file store, encrypted like the uploaded key, so a cluster's master
// keeps its certificate across restarts without a plain-text key file.
type acmeCache struct {
	config_obj *config_proto.Config
}

func cacheKey(key string) string {
	// autocert keys look like "console.example.com+rsa" or
	// "acme_account+key"; keep them readable but file-name safe.
	r := strings.NewReplacer("/", "_", "\\", "_", "..", "_")
	return r.Replace(key)
}

func (c acmeCache) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := readFile(c.config_obj, acmePath(cacheKey(key)))
	if err != nil || len(data) == 0 {
		return nil, autocert.ErrCacheMiss
	}
	plain, err := secrets.DecryptBlob(ctx, c.config_obj, data)
	if err != nil {
		return nil, autocert.ErrCacheMiss
	}
	return plain, nil
}

func (c acmeCache) Put(ctx context.Context, key string, data []byte) error {
	enc, err := secrets.EncryptBlob(ctx, c.config_obj, data)
	if err != nil {
		return err
	}
	return writeFile(c.config_obj, acmePath(cacheKey(key)), enc)
}

func (c acmeCache) Delete(ctx context.Context, key string) error {
	fs := file_store.GetFileStore(c.config_obj)
	if fs == nil {
		return errors.New("file store unavailable")
	}
	err := fs.Delete(acmePath(cacheKey(key)))
	if err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
