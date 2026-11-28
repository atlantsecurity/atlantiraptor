package auditlog

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
)

func TestValidateDirectory(t *testing.T) {
	base := t.TempDir()
	config_obj := &config_proto.Config{Datastore: &config_proto.DatastoreConfig{
		Location: filepath.Join(base, "datastore"), FilestoreDirectory: filepath.Join(base, "datastore")}}

	assert.NoError(t, ValidateDirectory(config_obj, ""))
	assert.NoError(t, ValidateDirectory(config_obj, filepath.Join(base, "audit")))
	assert.NoError(t, ValidateDirectory(config_obj, filepath.Join(base, "datastore-audit")))
	assert.Error(t, ValidateDirectory(config_obj, "relative/path"))
	assert.Error(t, ValidateDirectory(config_obj, filepath.Join(base, "datastore")))
	assert.Error(t, ValidateDirectory(config_obj, filepath.Join(base, "datastore", "audit")))
	// A parent of the datastore would hold it too.
	assert.Error(t, ValidateDirectory(config_obj, base))

	if runtime.GOOS != "windows" {
		assert.Equal(t, filepath.Join(base, "atlantiraptor-audit"), DefaultDirectory(config_obj))
	}
}

func TestEncodeDetails(t *testing.T) {
	assert.Equal(t, "{}", string(encodeDetails(nil)))
	big := map[string]string{"x": strings.Repeat("a", maxDetails+10)}
	var d map[string]interface{}
	assert.NoError(t, json.Unmarshal(encodeDetails(big), &d))
	assert.Equal(t, true, d["truncated"])
	assert.NotEmpty(t, d["sha256"])
}

func TestSyslogFormat(t *testing.T) {
	e := &Entry{Time: "2026-11-28T10:00:00Z"}
	msg := SyslogMessage("my host", e, []byte(`{"seq":1}`))
	assert.True(t, strings.HasPrefix(msg, "<133>1 2026-11-28T10:00:00Z my_host Atlantiraptor "), msg)
	assert.True(t, strings.HasSuffix(msg, ` audit - {"seq":1}`), msg)

	assert.True(t, validHostPort("siem.example.com:514"))
	assert.True(t, validHostPort("[2001:db8::1]:6514"))
	assert.False(t, validHostPort("siem.example.com"))
	assert.False(t, validHostPort("siem:abc"))
	assert.False(t, validHostPort("user@siem:514"))
}

func TestRecordBeforeStartIsQueued(t *testing.T) {
	defer resetForTests()
	resetForTests()
	assert.NoError(t, Record("root", "alice", "Login", map[string]string{"remote": "1.2.3.4"}))
	assert.Len(t, global.pending, 1)
}
