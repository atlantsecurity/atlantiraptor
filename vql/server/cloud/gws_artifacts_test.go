package cloud

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"www.velocidex.com/golang/velociraptor/constants"
)

func testServiceAccountJSON(t *testing.T) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pem_key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	data, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"client_email":   "hunter@atlant-test.iam.gserviceaccount.com",
		"private_key":    string(pem_key),
		"private_key_id": "k1",
		// A doctored token_uri must be ignored.
		"token_uri": "https://attacker.example/token",
	})
	return string(data)
}

type GWSArtifactsTestSuite struct {
	cloudSuite
	server *fixtureServer
	saved  [3]string
	key    string
}

func (self *GWSArtifactsTestSuite) SetupTest() {
	self.cloudSuite.SetupTest()

	self.server = newFixtureServer("gws")
	self.saved = [3]string{gwsTokenURL, gwsAdminBase, gwsGmailBase}
	gwsTokenURL = self.server.URL + "/token"
	gwsAdminBase = self.server.URL
	gwsGmailBase = self.server.URL
	resetTokenCache()

	if self.key == "" {
		self.key = testServiceAccountJSON(self.T())
	}

	self.loadArtifacts("Cloud/GoogleWorkspace/*.yaml")
	self.addSecret(constants.GWS_CREDS, "example", ordereddict.NewDict().
		Set("service_account_json", self.key).
		Set("admin_email", "admin@example.com"))
}

func (self *GWSArtifactsTestSuite) TearDownTest() {
	gwsTokenURL, gwsAdminBase, gwsGmailBase = self.saved[0], self.saved[1], self.saved[2]
	self.server.Close()
	self.cloudSuite.TearDownTest()
}

func (self *GWSArtifactsTestSuite) run(artifact string) []*ordereddict.Dict {
	return self.query("SELECT * FROM Artifact."+artifact+"(GWSSecret='example')", nil)
}

// subjects decodes the "sub" claims of the JWT assertions sent.
func (self *GWSArtifactsTestSuite) subjects() []string {
	var res []string
	for _, a := range self.server.assertions {
		parts := strings.Split(a, ".")
		if len(parts) != 3 {
			continue
		}
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		claims := map[string]interface{}{}
		_ = json.Unmarshal(payload, &claims)
		if sub, ok := claims["sub"].(string); ok {
			res = append(res, sub)
		}
	}
	return res
}

func (self *GWSArtifactsTestSuite) TestSignIns() {
	self.assertDetections(self.run("Cloud.GoogleWorkspace.SignIns"),
		"high|Google flagged a suspicious sign-in|bob@example.com",
		"critical|Google disabled the account as hijacked|dave@example.com",
		"high|Password spray from this address|11 accounts",
		"critical|Successful sign-in from a password-spraying address|carol@example.com",
		"medium|Sign-in from a new country|alice@example.com",
	)
	// Every token request was signed for the admin and went to the
	// fixed token URL, not the key file's token_uri.
	assert.NotEmpty(self.T(), self.subjects())
	for _, s := range self.subjects() {
		assert.Equal(self.T(), "admin@example.com", s)
	}
}

func (self *GWSArtifactsTestSuite) TestAccountChanges() {
	self.assertDetections(self.run("Cloud.GoogleWorkspace.AccountChanges"),
		"high|2-Step Verification turned off|erin@example.com",
		"medium|Account recovery details changed|frank@example.com",
	)
}

func (self *GWSArtifactsTestSuite) TestAdminChanges() {
	self.assertDetections(self.run("Cloud.GoogleWorkspace.AdminChanges"),
		"critical|Super admin granted|admin@example.com",
		"critical|Email monitor created (copies a user's mail)|admin@example.com",
		"critical|Domain-wide delegation granted to an API client|admin@example.com",
		"high|Admin role assigned|admin@example.com",
	)
}

func (self *GWSArtifactsTestSuite) TestOAuthApps() {
	self.assertDetections(self.run("Cloud.GoogleWorkspace.OAuthApps"),
		"critical|App seen in mailbox takeover cases|eM Client",
		"high|Users granted risky access to an app|Shady Reader",
	)
}

func (self *GWSArtifactsTestSuite) TestMailForwarding() {
	self.assertDetections(self.run("Cloud.GoogleWorkspace.MailForwarding"),
		"high|Mail automatically forwarded outside the domain|alice@example.com",
		"high|Filter forwards mail outside the domain|bob@example.com",
		"medium|Filter deletes or hides mail|bob@example.com",
		"medium|Forwarding address outside the domain added|carol@example.com",
	)
	// Gmail settings are read as each mailbox owner.
	subjects := self.subjects()
	assert.Contains(self.T(), subjects, "bob@example.com")
	assert.Contains(self.T(), subjects, "admin@example.com")
}

func (self *GWSArtifactsTestSuite) TestMassDownload() {
	self.assertDetections(self.run("Cloud.GoogleWorkspace.MassDownload"),
		"medium|Mass file download|bob@example.com",
	)
}

func (self *GWSArtifactsTestSuite) TestExternalSharing() {
	self.assertDetections(self.run("Cloud.GoogleWorkspace.ExternalSharing"),
		"high|Unusual amount of external sharing|carol@example.com",
		"medium|Files shared with personal mail addresses|dave@example.com",
	)
}

func (self *GWSArtifactsTestSuite) TestMonitor() {
	rows := self.query(`SELECT * FROM Artifact.Cloud.GoogleWorkspace.Monitor(
        source='Admin', GWSSecret='example') LIMIT 5`, nil)
	assert.Equal(self.T(), 5, len(rows))
	logs := self.logs()
	assert.Contains(self.T(), logs, "Google Workspace: Super admin granted (admin@example.com)")
	assert.Contains(self.T(), logs, "Google Workspace: Email monitor created")
	assert.NotContains(self.T(), logs, "Admin reset a user's password")
}

func (self *GWSArtifactsTestSuite) TestCompromiseAssessment() {
	found := detections(self.run("Cloud.GoogleWorkspace.CompromiseAssessment"))
	for _, expected := range []string{
		"critical|Super admin granted|admin@example.com",
		"high|Filter forwards mail outside the domain|bob@example.com",
		"medium|App authorised by users|Zoom",
	} {
		assert.Contains(self.T(), found, expected)
	}
}

func TestGWSArtifacts(t *testing.T) {
	suite.Run(t, &GWSArtifactsTestSuite{})
}

// The Reports API pages with nextPageToken.
func (self *GWSArtifactsTestSuite) TestReportsPaging() {
	self.server.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/applications/saml") {
			return false
		}
		tok := r.URL.Query().Get("pageToken")
		next := `,"nextPageToken":"p2"`
		if tok == "p2" {
			next = ""
		}
		fmt.Fprintf(w, `{"items":[{"id":{"time":"2026-11-27T10:00:00Z","uniqueQualifier":"%v1","applicationName":"saml"},
           "actor":{"email":"a@example.com"},"events":[{"name":"login_success","parameters":[]},{"name":"x","parameters":[]}]}]%v}`, tok, next)
		return true
	}
	rows := self.query(`SELECT * FROM gws_reports(secret="example", application="saml")`, nil)
	// Two pages of one activity with two events each.
	assert.Equal(self.T(), 4, len(rows))
}
