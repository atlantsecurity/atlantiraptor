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

type M365ArtifactsTestSuite struct {
	cloudSuite
	server *fixtureServer
	saved  [3]string

	started []string
}

func (self *M365ArtifactsTestSuite) SetupTest() {
	self.cloudSuite.SetupTest()

	self.server = newFixtureServer("m365")
	self.server.extra = self.managementAPI
	self.started = nil
	self.saved = [3]string{m365LoginBase, m365GraphBase, m365ManageBase}
	m365LoginBase = self.server.URL + "/login"
	m365GraphBase = self.server.URL
	m365ManageBase = self.server.URL
	resetTokenCache()

	self.loadArtifacts("Cloud/M365/*.yaml")
	self.addSecret(constants.M365_CREDS, "contoso", ordereddict.NewDict().
		Set("tenant_id", "11111111-2222-3333-4444-555555555555").
		Set("client_id", "app-id").
		Set("client_secret", "app-secret"))
}

// managementAPI fakes the Office 365 Management Activity API: no
// subscriptions at first, and one content blob per content type that is
// listed for every window (the plugin must read it once).
func (self *M365ArtifactsTestSuite) managementAPI(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "/activity/feed/subscriptions/list"):
		fmt.Fprint(w, `[]`)
	case strings.HasSuffix(path, "/activity/feed/subscriptions/start"):
		self.started = append(self.started, r.URL.Query().Get("contentType"))
		fmt.Fprint(w, `{"status":"enabled"}`)
	case strings.HasSuffix(path, "/activity/feed/subscriptions/content"):
		ct := r.URL.Query().Get("contentType")
		fmt.Fprintf(w, `[{"contentType":%q,"contentId":"%v-1","contentUri":"%v/auditcontent/%v","contentCreated":"x"}]`,
			ct, ct, self.server.URL, ct)
	default:
		return false
	}
	return true
}

func (self *M365ArtifactsTestSuite) TearDownTest() {
	m365LoginBase, m365GraphBase, m365ManageBase = self.saved[0], self.saved[1], self.saved[2]
	self.server.Close()
	self.cloudSuite.TearDownTest()
}

func (self *M365ArtifactsTestSuite) run(artifact string) []*ordereddict.Dict {
	return self.query("SELECT * FROM Artifact."+artifact+"(M365Secret='contoso')", nil)
}

func (self *M365ArtifactsTestSuite) TestSignIns() {
	self.assertDetections(self.run("Cloud.M365.SignIns"),
		"high|Sign-in from a new country|alice@contoso.com",
		"high|Impossible travel between sign-ins|alice@contoso.com",
		"medium|Successful sign-in with legacy authentication (no MFA possible)|bob@contoso.com",
		"high|High-risk sign-in succeeded|carol@contoso.com",
	)
}

func TestM365Artifacts(t *testing.T) {
	suite.Run(t, &M365ArtifactsTestSuite{})
}

func (self *M365ArtifactsTestSuite) TestTokenTheft() {
	self.assertDetections(self.run("Cloud.M365.TokenTheft"),
		"high|Session used from several countries (possible token theft)|erin@contoso.com",
		"medium|Session moved to another network|frank@contoso.com",
		"high|Entra ID Protection: anomalousToken|erin@contoso.com",
	)
}

func (self *M365ArtifactsTestSuite) TestPasswordSpray() {
	self.assertDetections(self.run("Cloud.M365.PasswordSpray"),
		"high|Password spray from this address|13 accounts",
		"critical|Successful sign-in from a password-spraying address|henry@contoso.com",
		"medium|Many failed sign-ins against one account|ivan@contoso.com",
	)
}

func (self *M365ArtifactsTestSuite) TestPrivilegedChanges() {
	self.assertDetections(self.run("Cloud.M365.PrivilegedChanges"),
		"critical|Admin role granted|admin@contoso.com",
		"critical|Domain federation or verification changed (forged sign-in risk)|admin@contoso.com",
		"high|Conditional Access policy changed|admin@contoso.com",
	)
}

func (self *M365ArtifactsTestSuite) TestAppChanges() {
	self.assertDetections(self.run("Cloud.M365.AppChanges"),
		"high|Secret or certificate added to an app|Payroll Sync",
		"high|Permissions granted to an app|bob@contoso.com",
		"medium|Owner added to an app|admin@contoso.com",
	)
}

func (self *M365ArtifactsTestSuite) TestMFAChanges() {
	self.assertDetections(self.run("Cloud.M365.MFAChanges"),
		"critical|MFA changed, then sign-in from a new country|alice@contoso.com",
		"medium|MFA method registered or changed|bob@contoso.com",
		// Carol's MFA was changed by an admin, then she signed in from France.
		"critical|MFA changed, then sign-in from a new country|carol@contoso.com",
	)
}

func (self *M365ArtifactsTestSuite) TestOAuthApps() {
	self.assertDetections(self.run("Cloud.M365.OAuthApps"),
		"critical|App seen in mailbox takeover cases|eM Client",
		"high|Users consented risky permissions to an app|Mail Helper",
		"high|App holds risky tenant-wide permissions|Exporter",
		"medium|App added recently|Zoom",
	)
}

func (self *M365ArtifactsTestSuite) TestInboxRules() {
	rows := self.run("Cloud.M365.InboxRules")
	self.assertDetections(rows,
		"high|Inbox rule forwards mail outside the organisation|alice@contoso.com",
		"medium|Inbox rule hides mail in a rarely read folder|bob@contoso.com",
	)
	// Dave has no mailbox: that is not an error worth logging.
	assert.NotContains(self.T(), self.logs(), "u-dave")
}

func (self *M365ArtifactsTestSuite) TestMailForwarding() {
	self.assertDetections(self.run("Cloud.M365.MailForwarding"),
		"high|Inbox rule forwards mail|alice@contoso.com",
		"high|Inbox rule with a blank or punctuation name|alice@contoso.com",
		"high|Mailbox forwarding set|admin@contoso.com",
		"medium|Full access to a mailbox granted|admin@contoso.com",
		"high|Transport rule copies or redirects mail|admin@contoso.com",
		"medium|Inbox rule that forwards or deletes changed from Outlook|carol@contoso.com",
	)
	// The subscription was started once, and the blob listed in all 7
	// daily windows was read once (one detection per record above).
	assert.Equal(self.T(), []string{"Audit.Exchange"}, self.started)
}

func (self *M365ArtifactsTestSuite) TestMassDownload() {
	self.assertDetections(self.run("Cloud.M365.MassDownload"),
		"medium|Mass file download|bob@contoso.com",
	)
}

func (self *M365ArtifactsTestSuite) TestExternalSharing() {
	self.assertDetections(self.run("Cloud.M365.ExternalSharing"),
		"high|Unusual amount of external sharing|carol@contoso.com",
		"medium|Files shared with personal mail addresses|dave@contoso.com",
	)
}

func (self *M365ArtifactsTestSuite) TestMonitorExchange() {
	rows := self.query(`SELECT * FROM Artifact.Cloud.M365.Monitor(
        source='ExchangeAudit', M365Secret='contoso', BackfillHours=48) LIMIT 6`, nil)
	assert.Equal(self.T(), 6, len(rows))

	logs := self.logs()
	assert.Contains(self.T(), logs, "Microsoft 365: Inbox rule forwards mail (alice@contoso.com)")
	assert.Contains(self.T(), logs, "Microsoft 365: Mailbox forwarding set (admin@contoso.com)")
	assert.Contains(self.T(), logs, "Microsoft 365: Transport rule copies or redirects mail (admin@contoso.com)")
	// Below the default alert level.
	assert.NotContains(self.T(), logs, "Full access to a mailbox granted")
	// Skipped operations are not collected.
	for _, r := range rows {
		op, _ := r.GetString("Operation")
		assert.NotEqual(self.T(), "MailItemsAccessed", op)
	}
}

func (self *M365ArtifactsTestSuite) TestMonitorDirectory() {
	rows := self.query(`SELECT * FROM Artifact.Cloud.M365.Monitor(
        source='DirectoryAudits', M365Secret='contoso') LIMIT 12`, nil)
	assert.Equal(self.T(), 12, len(rows))

	logs := self.logs()
	for _, expected := range []string{
		"Microsoft 365: Admin role granted (admin@contoso.com)",
		"Microsoft 365: Domain federation or verification changed (forged sign-in risk) (admin@contoso.com)",
		"Microsoft 365: Secret or certificate added to an app (Payroll Sync)",
		"Microsoft 365: Permissions granted to an app (bob@contoso.com)",
	} {
		assert.Contains(self.T(), logs, expected)
	}
	assert.NotContains(self.T(), logs, "Owner added to an app")
}

func (self *M365ArtifactsTestSuite) TestOAuthAppDetails() {
	for _, r := range self.run("Cloud.M365.OAuthApps") {
		user, _ := r.GetString("User")
		details_any, _ := r.Get("Details")
		details := details_any.(*ordereddict.Dict)
		grants, _ := details.Get("ConsentGrants")
		if user == "Mail Helper" {
			assert.EqualValues(self.T(), 1, grants)
		}
		if user == "Exporter" {
			perms, _ := details.GetString("AppPermissions")
			assert.Equal(self.T(), "Mail.Read", perms)
		}
	}
}

func (self *M365ArtifactsTestSuite) TestCompromiseAssessment() {
	rows := self.run("Cloud.M365.CompromiseAssessment")
	// Every hunt contributes; spot check a few from different sources.
	found := detections(rows)
	for _, expected := range []string{
		"critical|Admin role granted|admin@contoso.com",
		"critical|App seen in mailbox takeover cases|eM Client",
		"high|Inbox rule forwards mail|alice@contoso.com",
		"medium|Mass file download|bob@contoso.com",
		"high|Impossible travel between sign-ins|alice@contoso.com",
	} {
		assert.Contains(self.T(), found, expected)
	}
}
