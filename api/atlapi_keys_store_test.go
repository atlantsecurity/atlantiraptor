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

// Keys are written to a temporary file and moved into place, so the
// store on disk is always complete and no temporary file is left over.
func (self *APIKeyStoreTestSuite) TestWriteIsCompleteAndAtomic() {
	first, _, err := CreateAPIKey(self.ConfigObj, self.ConfigObj, "admin", "siem one", []string{apiKeyRoles[0]}, 0)
	assert.NoError(self.T(), err)
	second, _, err := CreateAPIKey(self.ConfigObj, self.ConfigObj, "admin", "siem two", []string{apiKeyRoles[0]}, 0)
	assert.NoError(self.T(), err)

	// Read back from the file store, not the cache.
	apiKeyCache = nil
	keys, err := ListAPIKeys(self.ConfigObj)
	assert.NoError(self.T(), err)
	ids := []string{}
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	assert.Contains(self.T(), ids, first.ID)
	assert.Contains(self.T(), ids, second.ID)

	fs := file_store.GetFileStore(self.ConfigObj)
	_, err = fs.StatFile(apiKeysTmpPath())
	assert.Error(self.T(), err)
}

func TestAPIKeyStore(t *testing.T) {
	suite.Run(t, &APIKeyStoreTestSuite{})
}
