package api

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"www.velocidex.com/golang/velociraptor/file_store"
	"www.velocidex.com/golang/velociraptor/file_store/test_utils"
	"www.velocidex.com/golang/velociraptor/vtesting/assert"
)

type APIKeyStoreTestSuite struct {
	test_utils.TestSuite
}

func (self *APIKeyStoreTestSuite) SetupTest() {
	self.ConfigObj = self.TestSuite.LoadConfig()
	self.TestSuite.SetupTest()
	apiKeyCache = nil
}

// Each write goes to a backup and then the main file, so a damaged main
// file (a crash mid-write) still reads back every key.
func (self *APIKeyStoreTestSuite) TestDamagedMainFileFallsBackToBackup() {
	first, _, err := CreateAPIKey(self.ConfigObj, self.ConfigObj, "admin", "siem one", []string{apiKeyRoles[0]}, 0)
	assert.NoError(self.T(), err)
	second, _, err := CreateAPIKey(self.ConfigObj, self.ConfigObj, "admin", "siem two", []string{apiKeyRoles[0]}, 0)
	assert.NoError(self.T(), err)

	// Truncate the main file half way, as a crash would.
	fs := file_store.GetFileStore(self.ConfigObj)
	w, err := fs.WriteFile(apiKeysPath())
	assert.NoError(self.T(), err)
	assert.NoError(self.T(), w.Truncate())
	_, err = w.Write([]byte(`{"keys":[{"id":`))
	assert.NoError(self.T(), err)
	assert.NoError(self.T(), w.Close())

	apiKeyCache = nil
	keys, err := ListAPIKeys(self.ConfigObj)
	assert.NoError(self.T(), err)
	ids := []string{}
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	assert.Contains(self.T(), ids, first.ID)
	assert.Contains(self.T(), ids, second.ID)
}

func TestAPIKeyStore(t *testing.T) {
	suite.Run(t, &APIKeyStoreTestSuite{})
}
