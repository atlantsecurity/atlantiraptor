package cloud

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"www.velocidex.com/golang/velociraptor/constants"
)

type OktaArtifactsTestSuite struct {
	cloudSuite
	server *fixtureServer
}

func (self *OktaArtifactsTestSuite) SetupTest() {
	self.cloudSuite.SetupTest()

	self.server = newFixtureServer("okta")
	oktaTestBase = self.server.URL

	self.loadArtifacts("Cloud/Okta/*.yaml")
	self.addSecret(constants.OKTA_CREDS, "example", ordereddict.NewDict().
		Set("org_url", "https://example.okta.com").
		Set("api_token", "test-token"))
}

func (self *OktaArtifactsTestSuite) TearDownTest() {
	oktaTestBase = ""
	self.server.Close()
	self.cloudSuite.TearDownTest()
}

func (self *OktaArtifactsTestSuite) run(artifact string) []*ordereddict.Dict {
	return self.query("SELECT * FROM Artifact."+artifact+"(OktaSecret='example')", nil)
}

func (self *OktaArtifactsTestSuite) TestSignIns() {
	self.assertDetections(self.run("Cloud.Okta.SignIns"),
		"medium|Sign-in from a new country|alice@example.com",
		"high|Impossible travel between sign-ins|bob@example.com",
		"high|Successful sign-in through an anonymising proxy or Tor|dave@example.com",
		"high|High-risk sign-in succeeded|ivy@example.com",
		"high|User reported suspicious activity on their account|jane@example.com",
		"medium|Okta ThreatInsight flagged sign-in attempts|unknown",
	)
}

func (self *OktaArtifactsTestSuite) TestPasswordSpray() {
	self.assertDetections(self.run("Cloud.Okta.PasswordSpray"),
		"high|Password spray from this address|11 accounts",
		"critical|Successful sign-in from a password-spraying address|carol@example.com",
		"medium|Brute force against one account|hank@example.com",
		"high|Successful sign-in after brute force|hank@example.com",
	)
}

func (self *OktaArtifactsTestSuite) TestMFAFatigue() {
	self.assertDetections(self.run("Cloud.Okta.MFAFatigue"),
		"critical|MFA approved after repeated push prompts|erin@example.com",
		"medium|Burst of MFA push prompts|erin@example.com",
	)
}

func (self *OktaArtifactsTestSuite) TestSessionHijack() {
	rows := self.run("Cloud.Okta.SessionHijack")
	self.assertDetections(rows,
		"critical|Okta session used from several countries, including the Admin Console|gina@example.com",
	)
	if len(rows) == 1 {
		ip, _ := rows[0].GetString("IPAddress")
		assert.Equal(self.T(), "203.0.113.99", ip)
	}
}

func (self *OktaArtifactsTestSuite) TestFactorChanges() {
	self.assertDetections(self.run("Cloud.Okta.FactorChanges"),
		"critical|MFA or password reset by someone else, then a new factor enrolled|frank@example.com",
		"high|All MFA factors reset by admin@example.com|frank@example.com",
		"medium|MFA factor removed|kate@example.com",
	)
}

func (self *OktaArtifactsTestSuite) TestAdminChanges() {
	self.assertDetections(self.run("Cloud.Okta.AdminChanges"),
		"critical|Identity provider added (can sign users in)|admin@example.com",
		"critical|Admin role granted|admin@example.com",
		"high|API token created|admin@example.com",
		"high|Sign-on or MFA policy disabled or deleted|admin@example.com",
		"medium|Network zone changed|admin@example.com",
	)
}

func (self *OktaArtifactsTestSuite) TestPersistence() {
	self.assertDetections(self.run("Cloud.Okta.Persistence"),
		"low|Identity provider configured|Corp SAML",
		"high|Identity provider created recently|Okta Sync",
		"high|API token created recently|Backup tool",
		"low|API token exists|SIEM",
	)
}

func (self *OktaArtifactsTestSuite) TestMonitor() {
	rows := self.query(`SELECT * FROM Artifact.Cloud.Okta.Monitor(
        OktaSecret='example') LIMIT 70`, nil)
	assert.Equal(self.T(), 70, len(rows))
	logs := self.logs()
	assert.Contains(self.T(), logs, "Okta: Identity provider added (can sign users in) (Okta Sync)")
	assert.Contains(self.T(), logs, "Okta: Admin role granted (mallory@example.com)")
	// Below the default alert level, or a failed attempt.
	assert.NotContains(self.T(), logs, "Network zone changed")
	assert.NotContains(self.T(), logs, "Policy rule disabled or deleted")
}

func (self *OktaArtifactsTestSuite) TestCompromiseAssessment() {
	found := detections(self.run("Cloud.Okta.CompromiseAssessment"))
	for _, expected := range []string{
		"critical|MFA approved after repeated push prompts|erin@example.com",
		"critical|Identity provider added (can sign users in)|admin@example.com",
		"high|Identity provider created recently|Okta Sync",
	} {
		assert.Contains(self.T(), found, expected)
	}
}

// The System Log pages with Link headers; links off the org are refused.
func (self *OktaArtifactsTestSuite) TestLogPaging() {
	self.server.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/v1/logs" {
			return false
		}
		assert.Equal(self.T(), "SSWS test-token", r.Header.Get("Authorization"))
		page := r.URL.Query().Get("after")
		switch page {
		case "":
			w.Header().Add("Link", fmt.Sprintf(`<%v/api/v1/logs?after=p2>; rel="next"`, self.server.URL))
		case "p2":
			w.Header().Add("Link", `<https://attacker.example/api/v1/logs?after=p3>; rel="next"`)
		default:
			self.T().Errorf("followed a link off the org: %v", r.URL)
		}
		fmt.Fprintf(w, `[{"uuid":"u-%v","published":"2026-11-27T10:00:00.000Z","eventType":"user.session.start",
            "actor":{"alternateId":"a@example.com"},"outcome":{"result":"SUCCESS"}}]`, page)
		return true
	}
	rows := self.query(`SELECT UUID FROM okta_logs(secret="example")`, nil)
	assert.Equal(self.T(), 2, len(rows))
	for _, req := range self.server.requests {
		assert.False(self.T(), strings.Contains(req, "p3"), req)
	}
}

func TestOktaArtifacts(t *testing.T) {
	suite.Run(t, &OktaArtifactsTestSuite{})
}
