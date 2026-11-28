package cloud

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"www.velocidex.com/golang/velociraptor/constants"
)

// The region and service a SigV4 request was signed for.
var awsScope = regexp.MustCompile(`Credential=([^/]+)/\d+/([^/]+)/([^/]+)/aws4_request`)

type AWSArtifactsTestSuite struct {
	cloudSuite
	server *fixtureServer
	// "key region service" of every signed request. Regions are read
	// in parallel, so the handler runs concurrently.
	mu     sync.Mutex
	signed []string
}

func (self *AWSArtifactsTestSuite) SetupTest() {
	self.cloudSuite.SetupTest()

	self.signed = nil
	self.server = newFixtureServer("aws")
	self.server.extra = self.handle
	awsTestBase = self.server.URL
	awsPageDelay = 0
	resetAWSProviders()

	self.loadArtifacts("Cloud/AWS/*.yaml")
	self.addSecret(constants.AWS_CREDS, "example", ordereddict.NewDict().
		Set("access_key_id", "AKIAATLANT").
		Set("secret_access_key", "test-secret"))
	self.addSecret(constants.AWS_CREDS, "assume", ordereddict.NewDict().
		Set("access_key_id", "AKIAATLANT").
		Set("secret_access_key", "test-secret").
		Set("role_arn", "arn:aws:iam::123456789012:role/AtlantiraptorAudit").
		Set("external_id", "atlant-ext-1").
		Set("regions", "eu-west-1"))
}

func (self *AWSArtifactsTestSuite) TearDownTest() {
	awsTestBase = ""
	awsPageDelay = 500 * time.Millisecond
	self.server.Close()
	self.cloudSuite.TearDownTest()
}

func (self *AWSArtifactsTestSuite) fixture(name string) []byte {
	data, err := os.ReadFile(filepath.Join("fixtures", "aws", name))
	if err != nil {
		return nil
	}
	return expandTimes(data, self.server.now)
}

func (self *AWSArtifactsTestSuite) handle(w http.ResponseWriter, r *http.Request) bool {
	body, _ := io.ReadAll(r.Body)

	m := awsScope.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil {
		http.Error(w, "unsigned", 403)
		return true
	}
	key, region, service := m[1], m[2], m[3]
	self.mu.Lock()
	self.signed = append(self.signed, key+" "+region+" "+service)
	self.mu.Unlock()

	if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".LookupEvents") {
		self.lookupEvents(w, region, body)
		return true
	}

	form, _ := url.ParseQuery(string(body))
	w.Header().Set("Content-Type", "text/xml")
	switch action := form.Get("Action"); action {
	case "AssumeRole":
		if form.Get("ExternalId") != "atlant-ext-1" {
			w.WriteHeader(403)
			fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>AssumeRole denied</Message></Error></ErrorResponse>`)
			return true
		}
		fmt.Fprint(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials>
            <AccessKeyId>ASIATEMP</AccessKeyId><SecretAccessKey>temp-secret</SecretAccessKey>
            <SessionToken>temp-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>
            </Credentials><AssumedRoleUser><AssumedRoleId>AROA:atlantiraptor</AssumedRoleId>
            <Arn>arn:aws:sts::123456789012:assumed-role/AtlantiraptorAudit/atlantiraptor</Arn>
            </AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`)
	case "DescribeRegions":
		fmt.Fprint(w, `<DescribeRegionsResponse><regionInfo>
            <item><regionName>us-east-1</regionName></item>
            <item><regionName>eu-west-1</regionName></item>
            <item><regionName>ap-southeast-1</regionName></item>
            </regionInfo></DescribeRegionsResponse>`)
	case "GenerateCredentialReport":
		fmt.Fprint(w, `<GenerateCredentialReportResponse><GenerateCredentialReportResult>
            <State>COMPLETE</State></GenerateCredentialReportResult></GenerateCredentialReportResponse>`)
	case "GetCredentialReport":
		fmt.Fprintf(w, `<GetCredentialReportResponse><GetCredentialReportResult>
            <Content>%v</Content><ReportFormat>text/csv</ReportFormat>
            </GetCredentialReportResult></GetCredentialReportResponse>`,
			base64.StdEncoding.EncodeToString(self.fixture("credential_report.csv")))
	default:
		data := self.fixture("iam." + action + ".xml")
		if data == nil {
			w.WriteHeader(404)
			fmt.Fprintf(w, `<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>no fixture for %v</Message></Error></ErrorResponse>`, action)
			return true
		}
		w.Write(data)
	}
	return true
}

// lookupEvents behaves like CloudTrail: filters by time and one lookup
// attribute, newest first, in pages.
func (self *AWSArtifactsTestSuite) lookupEvents(w http.ResponseWriter, region string, body []byte) {
	req := struct {
		StartTime        float64
		EndTime          float64
		NextToken        string
		LookupAttributes []struct{ AttributeKey, AttributeValue string }
	}{}
	_ = json.Unmarshal(body, &req)

	var records []map[string]interface{}
	_ = json.Unmarshal(self.fixture("cloudtrail."+region+".json"), &records)

	type item struct {
		t     time.Time
		event map[string]interface{}
	}
	var matched []item
	for _, rec := range records {
		t, _ := time.Parse(time.RFC3339, rec["eventTime"].(string))
		if float64(t.Unix()) < req.StartTime || float64(t.Unix()) > req.EndTime {
			continue
		}
		identity, _ := rec["userIdentity"].(map[string]interface{})
		username, _ := identity["userName"].(string)
		if identity["type"] == "Root" {
			username = "root"
		}
		values := map[string]string{
			"EventName":   fmt.Sprint(rec["eventName"]),
			"EventSource": fmt.Sprint(rec["eventSource"]),
			"Username":    username,
			"AccessKeyId": fmt.Sprint(identity["accessKeyId"]),
			"ReadOnly":    fmt.Sprint(rec["readOnly"]),
		}
		ok := true
		for _, a := range req.LookupAttributes {
			if values[a.AttributeKey] != a.AttributeValue {
				ok = false
			}
		}
		if ok {
			matched = append(matched, item{t: t, event: rec})
		}
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].t.After(matched[j].t) })

	const page_size = 5
	offset, _ := strconv.Atoi(req.NextToken)
	end := offset + page_size
	next := strconv.Itoa(end)
	if end >= len(matched) {
		end = len(matched)
		next = ""
	}

	var events []map[string]interface{}
	for _, m := range matched[offset:end] {
		raw, _ := json.Marshal(m.event)
		identity, _ := m.event["userIdentity"].(map[string]interface{})
		events = append(events, map[string]interface{}{
			"EventId":         m.event["eventID"],
			"EventName":       m.event["eventName"],
			"EventSource":     m.event["eventSource"],
			"ReadOnly":        fmt.Sprint(m.event["readOnly"]),
			"AccessKeyId":     identity["accessKeyId"],
			"EventTime":       m.t.Unix(),
			"CloudTrailEvent": string(raw),
		})
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"Events": events, "NextToken": next})
}

func (self *AWSArtifactsTestSuite) run(artifact string) []*ordereddict.Dict {
	return self.query("SELECT * FROM Artifact."+artifact+"(AWSSecret='example')", nil)
}

func (self *AWSArtifactsTestSuite) TestConsoleLogins() {
	self.assertDetections(self.run("Cloud.AWS.ConsoleLogins"),
		"critical|Root user signed in to the console|root",
		"medium|Console sign-in without MFA|bob",
		"high|Password guessing against many IAM users|5 users",
		"critical|Successful console sign-in from a password-guessing address|carol",
	)
	// Every region was read, each request signed for its own region.
	self.mu.Lock()
	defer self.mu.Unlock()
	assert.Contains(self.T(), self.signed, "AKIAATLANT eu-west-1 cloudtrail")
	assert.Contains(self.T(), self.signed, "AKIAATLANT ap-southeast-1 cloudtrail")
}

func (self *AWSArtifactsTestSuite) TestRootActivity() {
	self.assertDetections(self.run("Cloud.AWS.RootActivity"),
		"high|Root user made changes|root",
		"medium|Root user made read-only calls|root",
	)
}

func (self *AWSArtifactsTestSuite) TestAccessKeyAbuse() {
	self.assertDetections(self.run("Cloud.AWS.AccessKeyAbuse"),
		"high|Access key used by an attack tool|backup-bot",
		"medium|Long-term access key used from a new address|svc-deploy",
	)
}

func (self *AWSArtifactsTestSuite) TestSuspiciousChanges() {
	self.assertDetections(self.run("Cloud.AWS.SuspiciousChanges"),
		"critical|Access key created|root",
		"medium|Access key created|dev-intern",
		"medium|Access key created|alice",
		"high|Access key created for another user|dev-intern",
		"critical|Managed policy attached|dev-intern",
		"high|Console password set for an IAM user|dev-intern",
		"high|Role trust policy changed (who can assume the role)|dev-intern",
		"critical|CloudTrail logging stopped or trail deleted|dev-intern",
		"critical|GuardDuty turned off|dev-intern",
		"high|Bucket policy changed|dev-intern",
		"critical|EBS snapshot shared with another account|dev-intern",
		"high|Instances launched|dev-intern",
		"high|Instances launched in a region the account does not otherwise use|dev-intern",
		"medium|Bedrock model availability checked (LLMjacking reconnaissance)|lambda-exec/i-123",
	)
}

func (self *AWSArtifactsTestSuite) TestIAMPosture() {
	self.assertDetections(self.run("Cloud.AWS.IAMPosture"),
		"critical|Root user has access keys|root",
		"critical|Root user has no MFA|root",
		"medium|Root user signed in recently|root",
		"high|Console user without MFA|bob",
		"low|Active access key not rotated for a long time|bob",
		"low|Active access key unused for a long time|alice",
	)
}

func (self *AWSArtifactsTestSuite) TestPersistence() {
	self.assertDetections(self.run("Cloud.AWS.Persistence"),
		"critical|Role anyone can assume|backdoor",
		"high|Role another AWS account can assume|vendor-x",
		"medium|Role another AWS account can assume|OrganizationAccountAccessRole",
		"high|SAML identity provider configured|EvilIdP",
		"low|OpenID Connect identity provider configured|token.actions.githubusercontent.com",
	)

	// Accounts in TrustedAccounts are not reported.
	rows := self.query(`SELECT * FROM Artifact.Cloud.AWS.Persistence(
        AWSSecret='example', TrustedAccounts='^(111111111111)$')`, nil)
	assert.NotContains(self.T(), detections(rows),
		"medium|Role another AWS account can assume|OrganizationAccountAccessRole")
}

func (self *AWSArtifactsTestSuite) TestMonitor() {
	rows := self.query(`SELECT * FROM Artifact.Cloud.AWS.Monitor(
        AWSSecret='example', BackfillHours=720) LIMIT 31`, nil)
	assert.Equal(self.T(), 31, len(rows))
	logs := self.logs()
	assert.Contains(self.T(), logs, "AWS: CloudTrail logging stopped or trail deleted (dev-intern)")
	assert.Contains(self.T(), logs, "AWS: Root user signed in to the console (root)")
	assert.Contains(self.T(), logs, "AWS: Root user made changes (root)")
	assert.Contains(self.T(), logs, "AWS: GuardDuty turned off (dev-intern)")
	// Below the alert level, or denied.
	assert.NotContains(self.T(), logs, "Instances launched (alice)")
	assert.NotContains(self.T(), logs, "Bucket ACL changed")
}

func (self *AWSArtifactsTestSuite) TestCompromiseAssessment() {
	found := detections(self.run("Cloud.AWS.CompromiseAssessment"))
	for _, expected := range []string{
		"critical|Root user signed in to the console|root",
		"critical|CloudTrail logging stopped or trail deleted|dev-intern",
		"critical|Role anyone can assume|backdoor",
		"critical|Root user has access keys|root",
	} {
		assert.Contains(self.T(), found, expected)
	}
}

// With role_arn, Atlant's key only calls sts:AssumeRole (with the
// external ID); the customer account is read with the temporary keys.
func (self *AWSArtifactsTestSuite) TestAssumeRole() {
	rows := self.query(`SELECT EventName FROM foreach(
        row={ SELECT Region FROM aws_regions(secret="assume") },
        query={ SELECT * FROM aws_cloudtrail(secret="assume", region=Region,
                                             start=now() - 30 * 86400) })`, nil)
	assert.Equal(self.T(), 6, len(rows), self.logs())
	self.mu.Lock()
	defer self.mu.Unlock()
	assert.Contains(self.T(), self.signed, "AKIAATLANT us-east-1 sts")
	assert.Contains(self.T(), self.signed, "ASIATEMP eu-west-1 cloudtrail")
	for _, s := range self.signed {
		if strings.HasPrefix(s, "AKIAATLANT") {
			assert.Equal(self.T(), "AKIAATLANT us-east-1 sts", s)
		}
	}
}

func TestAWSArtifacts(t *testing.T) {
	suite.Run(t, &AWSArtifactsTestSuite{})
}
