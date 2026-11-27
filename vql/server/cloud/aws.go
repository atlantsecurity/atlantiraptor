/*
Atlantiraptor - cloud breach hunting.
Copyright (C) 2026 Atlant Security EOOD.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package cloud

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/vfilter"
)

// AWS endpoints are built here from a validated region, never taken
// from a query, so signed requests only go to amazonaws.com.
var awsRegionRe = regexp.MustCompile(`^(us|eu|ap|sa|ca|me|af|il|mx)(-gov)?-[a-z]+-[0-9]$`)

// awsTestBase sends every AWS request to a fixture server in tests.
var awsTestBase = ""

func awsEndpoint(service, region string) (string, error) {
	if awsTestBase != "" {
		return awsTestBase, nil
	}
	switch service {
	case "iam":
		if strings.HasPrefix(region, "us-gov-") {
			return "https://iam.us-gov.amazonaws.com", nil
		}
		return "https://iam.amazonaws.com", nil
	case "sts":
		if strings.HasPrefix(region, "us-gov-") {
			return "https://sts.us-gov-west-1.amazonaws.com", nil
		}
		return "https://sts.amazonaws.com", nil
	}
	if !awsRegionRe.MatchString(region) {
		return "", fmt.Errorf("invalid AWS region %q", region)
	}
	return fmt.Sprintf("https://%v.%v.amazonaws.com", service, region), nil
}

// The region that signs global (IAM, STS) requests.
func awsGlobalRegion(region string) string {
	if strings.HasPrefix(region, "us-gov-") {
		return "us-gov-west-1"
	}
	return "us-east-1"
}

type awsCreds struct {
	Secret          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	RoleARN         string
	ExternalID      string
	Regions         string
}

func (self *awsCreds) resolve(ctx context.Context, scope vfilter.Scope) error {
	err := secretsEnforced(scope, self.Secret)
	if err != nil {
		return err
	}

	if self.Secret != "" {
		s, err := getSecret(ctx, scope, constants.AWS_CREDS, self.Secret)
		if err != nil {
			return err
		}
		s.UpdateString("access_key_id", &self.AccessKeyID)
		s.UpdateString("secret_access_key", &self.SecretAccessKey)
		s.UpdateString("session_token", &self.SessionToken)
		s.UpdateString("role_arn", &self.RoleARN)
		s.UpdateString("external_id", &self.ExternalID)
		s.UpdateString("regions", &self.Regions)
	}

	if self.AccessKeyID == "" || self.SecretAccessKey == "" {
		return errors.New("no credentials: name an 'AWS Creds' secret with secret=, " +
			"or give access_key_id and secret_access_key")
	}
	if self.RoleARN != "" && !strings.HasPrefix(self.RoleARN, "arn:aws") {
		return fmt.Errorf("role_arn %q is not an IAM role ARN", self.RoleARN)
	}
	return nil
}

// RegionList is the regions named in the credential, if any.
func (self *awsCreds) RegionList() []string {
	var res []string
	for _, r := range strings.FieldsFunc(self.Regions, func(c rune) bool {
		return c == ',' || c == ' ' || c == ';'
	}) {
		if awsRegionRe.MatchString(r) {
			res = append(res, r)
		}
	}
	return res
}

var (
	awsProvidersMu sync.Mutex
	awsProviders   = make(map[string]aws.CredentialsProvider)
)

func resetAWSProviders() {
	awsProvidersMu.Lock()
	defer awsProvidersMu.Unlock()
	awsProviders = make(map[string]aws.CredentialsProvider)
}

// provider returns cached credentials: the static keys, or temporary
// keys for role_arn obtained with them (cross-account access with an
// external ID).
func (self *awsCreds) provider(transport http.RoundTripper, region string) (
	aws.CredentialsProvider, error) {
	sts_base, err := awsEndpoint("sts", region)
	if err != nil {
		return nil, err
	}

	key := cacheKey("aws", sts_base, self.AccessKeyID, self.SecretAccessKey,
		self.SessionToken, self.RoleARN, self.ExternalID)

	awsProvidersMu.Lock()
	defer awsProvidersMu.Unlock()

	if p, pres := awsProviders[key]; pres {
		return p, nil
	}

	var p aws.CredentialsProvider = credentials.NewStaticCredentialsProvider(
		self.AccessKeyID, self.SecretAccessKey, self.SessionToken)

	if self.RoleARN != "" {
		client := sts.New(sts.Options{
			Region:       awsGlobalRegion(region),
			Credentials:  p,
			HTTPClient:   &http.Client{Transport: transport, Timeout: 30 * time.Second},
			BaseEndpoint: aws.String(sts_base),
		})
		external_id := self.ExternalID
		p = stscreds.NewAssumeRoleProvider(client, self.RoleARN,
			func(o *stscreds.AssumeRoleOptions) {
				o.RoleSessionName = "atlantiraptor"
				o.Duration = time.Hour
				if external_id != "" {
					o.ExternalID = aws.String(external_id)
				}
			})
	}

	p = aws.NewCredentialsCache(p)
	awsProviders[key] = p
	return p, nil
}

// awsSigningTransport signs each request with SigV4, only for the host
// it was made for.
type awsSigningTransport struct {
	base     http.RoundTripper
	host     string
	service  string
	region   string
	provider aws.CredentialsProvider
	signer   *v4.Signer
}

func (self *awsSigningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != self.host {
		return nil, fmt.Errorf("refusing to sign a request for %v", req.URL.Host)
	}

	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	creds, err := self.provider.Retrieve(req.Context())
	if err != nil {
		return nil, fmt.Errorf("AWS credentials: %w", err)
	}

	req = req.Clone(req.Context())
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	hash := sha256.Sum256(body)

	err = self.signer.SignHTTP(req.Context(), creds, req, hex.EncodeToString(hash[:]),
		self.service, self.region, time.Now())
	if err != nil {
		return nil, err
	}
	return self.base.RoundTrip(req)
}

// client returns an API client that signs for one service and region,
// and its endpoint.
func (self *awsCreds) client(scope vfilter.Scope, name, service, region string) (
	*apiClient, string, error) {
	endpoint, err := awsEndpoint(service, region)
	if err != nil {
		return nil, "", err
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, "", err
	}

	transport, err := baseTransport(scope)
	if err != nil {
		return nil, "", err
	}

	provider, err := self.provider(transport, region)
	if err != nil {
		return nil, "", err
	}

	signing_region := region
	if service == "iam" || service == "sts" {
		signing_region = awsGlobalRegion(region)
	}

	client := newAPIClient(name, &http.Client{
		Transport: &awsSigningTransport{
			base: transport, host: u.Host, service: service,
			region: signing_region, provider: provider, signer: v4.NewSigner(),
		},
		Timeout: 5 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	})
	client.retryIf = awsThrottled
	return client, endpoint, nil
}

func awsThrottled(status int, body []byte) bool {
	if status != 400 {
		return false
	}
	return bytes.Contains(body, []byte("Throttling")) ||
		bytes.Contains(body, []byte("RequestLimitExceeded")) ||
		bytes.Contains(body, []byte("TooManyRequests"))
}

func describeAWSError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "AccessDenied") && strings.Contains(msg, "AssumeRole"):
		return msg + " (the trust policy of the role must allow the Atlant account with this " +
			"external ID: see docs/cloud/aws.md)"
	case strings.Contains(msg, "AccessDenied") || strings.Contains(msg, "UnauthorizedOperation"):
		return msg + " (the role lacks a read permission: attach the SecurityAudit " +
			"managed policy, see docs/cloud/aws.md)"
	case strings.Contains(msg, "InvalidClientTokenId") ||
		strings.Contains(msg, "SignatureDoesNotMatch"):
		return msg + " (the access key is invalid or deactivated)"
	case strings.Contains(msg, "UnrecognizedClientException") ||
		strings.Contains(msg, "OptInRequired"):
		return msg + " (the region is not enabled for this account)"
	}
	return msg
}

// awsQuery posts an AWS Query protocol request (IAM, EC2) and returns
// the XML answer.
func awsQuery(ctx context.Context, client *apiClient, endpoint string,
	params url.Values) ([]byte, error) {
	_, data, err := client.do(ctx, request{
		Method: "POST",
		URL:    endpoint + "/",
		Body:   []byte(params.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
			"Accept":       "text/xml",
		},
	})
	return data, err
}
