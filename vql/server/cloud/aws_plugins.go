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
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

// LookupEvents allows 2 requests a second per region. Tests set 0.
var awsPageDelay = 500 * time.Millisecond

// Regions used when the credential names none and the account may not
// call ec2:DescribeRegions.
var awsDefaultRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"ca-central-1", "sa-east-1",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
	"ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
	"ap-northeast-2", "ap-northeast-3",
}

// ---------------------------------------------------------------------
// aws_cloudtrail()

type awsCloudTrailArgs struct {
	Secret          string      `vfilter:"optional,field=secret,doc=Name of an 'AWS Creds' secret."`
	AccessKeyID     string      `vfilter:"optional,field=access_key_id,doc=Access key ID when no secret is used."`
	SecretAccessKey string      `vfilter:"optional,field=secret_access_key,doc=Secret access key when no secret is used."`
	SessionToken    string      `vfilter:"optional,field=session_token,doc=Session token for temporary keys."`
	RoleARN         string      `vfilter:"optional,field=role_arn,doc=Role to assume in the customer account."`
	ExternalID      string      `vfilter:"optional,field=external_id,doc=External ID that the trust policy of the role requires."`
	Region          string      `vfilter:"required,field=region,doc=AWS region to read, e.g. us-east-1 (global services such as IAM and console sign-in log there)."`
	EventName       string      `vfilter:"optional,field=event_name,doc=Only events with this name."`
	EventSource     string      `vfilter:"optional,field=event_source,doc=Only events from this service, e.g. iam.amazonaws.com."`
	Username        string      `vfilter:"optional,field=username,doc=Only events by this user name (root for the root user)."`
	AccessKey       string      `vfilter:"optional,field=access_key,doc=Only events made with this access key ID."`
	ReadOnly        string      `vfilter:"optional,field=read_only,doc=true or false: only read-only or only changing events."`
	Start           vfilter.Any `vfilter:"optional,field=start,doc=Only events at or after this time (default 24 hours ago, at most 90 days)."`
	End             vfilter.Any `vfilter:"optional,field=end,doc=Only events before this time."`
	MaxRows         int64       `vfilter:"optional,field=max_rows,doc=Stop after this many rows."`
	Follow          bool        `vfilter:"optional,field=follow,doc=Keep polling for new events. Use in event artifacts."`
	Poll            int64       `vfilter:"optional,field=poll,doc=Seconds between polls in follow mode (default 300)."`
	Overlap         int64       `vfilter:"optional,field=overlap,doc=Seconds each poll re-reads before the last one (default 1800: CloudTrail delivers events up to 15 minutes late)."`
}

func (self *awsCloudTrailArgs) creds() *awsCreds {
	return &awsCreds{Secret: self.Secret, AccessKeyID: self.AccessKeyID,
		SecretAccessKey: self.SecretAccessKey, SessionToken: self.SessionToken,
		RoleARN: self.RoleARN, ExternalID: self.ExternalID}
}

type AWSCloudTrailPlugin struct{}

func (self AWSCloudTrailPlugin) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "aws_cloudtrail",
		Doc: "Read AWS CloudTrail management events of one region (LookupEvents, the " +
			"last 90 days). One row per event, with the identity, request and " +
			"response flattened.",
		ArgType:  type_map.AddType(scope, &awsCloudTrailArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(acls.NETWORK).Build(),
	}
}

func (self AWSCloudTrailPlugin) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "aws_cloudtrail", args)()

		err := vql_subsystem.CheckAccess(scope, acls.NETWORK)
		if err != nil {
			scope.Log("aws_cloudtrail: %v", err)
			return
		}

		arg := &awsCloudTrailArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("aws_cloudtrail: %v", err)
			return
		}

		creds := arg.creds()
		err = creds.resolve(ctx, scope)
		if err != nil {
			scope.Log("aws_cloudtrail: %v", err)
			return
		}

		start, err := optionalTime(ctx, scope, arg.Start)
		if err != nil {
			scope.Log("aws_cloudtrail: start: %v", err)
			return
		}
		end, err := optionalTime(ctx, scope, arg.End)
		if err != nil {
			scope.Log("aws_cloudtrail: end: %v", err)
			return
		}
		if start.IsZero() {
			start = time.Now().Add(-24 * time.Hour)
		}
		if oldest := time.Now().Add(-90 * 24 * time.Hour); start.Before(oldest) {
			start = oldest
		}

		client, endpoint, err := creds.client(scope, "aws_cloudtrail", "cloudtrail", arg.Region)
		if err != nil {
			scope.Log("aws_cloudtrail: %v", err)
			return
		}

		r := &awsTrailReader{arg: arg, client: client, endpoint: endpoint,
			output: output_chan}

		if !arg.Follow {
			if end.IsZero() {
				end = time.Now()
			}
			_, err := r.read(ctx, start, end, nil)
			if err != nil {
				scope.Log("aws_cloudtrail: %v: %v", arg.Region, describeAWSError(err))
			}
			return
		}

		poll := secondsOr(arg.Poll, 300)
		overlap := secondsOr(arg.Overlap, 1800)
		seen := newSeenSet(overlap + 2*poll + time.Hour)
		window := &pollWindow{next: start, overlap: overlap}
		read_from := start
		for {
			now := time.Now()
			more, err := r.read(ctx, read_from, now, seen)
			if err != nil {
				scope.Log("aws_cloudtrail: %v: %v", arg.Region, describeAWSError(err))
			} else {
				window.Advance(now)
			}
			if !more {
				return
			}
			seen.Prune(now)
			if !sleepCtx(ctx, poll) {
				return
			}
			read_from = window.Start()
		}
	}()

	return output_chan
}

type awsTrailReader struct {
	arg      *awsCloudTrailArgs
	client   *apiClient
	endpoint string
	output   chan vfilter.Row
	count    int64
}

type awsLookupEventsPage struct {
	Events []struct {
		EventID         string            `json:"EventId"`
		EventName       string            `json:"EventName"`
		EventSource     string            `json:"EventSource"`
		ReadOnly        string            `json:"ReadOnly"`
		AccessKeyID     string            `json:"AccessKeyId"`
		Username        string            `json:"Username"`
		Resources       []json.RawMessage `json:"Resources"`
		CloudTrailEvent string            `json:"CloudTrailEvent"`
	} `json:"Events"`
	NextToken string `json:"NextToken"`
}

func (self *awsTrailReader) read(ctx context.Context, start, end time.Time,
	seen *seenSet) (bool, error) {

	req := map[string]interface{}{
		"StartTime":  start.Unix(),
		"EndTime":    end.Unix(),
		"MaxResults": 50,
	}
	// LookupEvents takes a single lookup attribute.
	for _, attr := range []struct{ key, value string }{
		{"EventName", self.arg.EventName},
		{"EventSource", self.arg.EventSource},
		{"Username", self.arg.Username},
		{"AccessKeyId", self.arg.AccessKey},
		{"ReadOnly", self.arg.ReadOnly},
	} {
		if attr.value != "" {
			req["LookupAttributes"] = []map[string]string{
				{"AttributeKey": attr.key, "AttributeValue": attr.value}}
			break
		}
	}

	for page_count := 0; ; page_count++ {
		if page_count > 0 && awsPageDelay > 0 && !self.client.sleep(ctx, awsPageDelay) {
			return false, nil
		}

		body, _ := json.Marshal(req)
		_, data, err := self.client.do(ctx, request{
			Method: "POST",
			URL:    self.endpoint + "/",
			Body:   body,
			Headers: map[string]string{
				"Content-Type": "application/x-amz-json-1.1",
				"X-Amz-Target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents",
			},
		})
		if err != nil {
			return true, err
		}

		page := &awsLookupEventsPage{}
		err = json.Unmarshal(data, page)
		if err != nil {
			return true, fmt.Errorf("invalid LookupEvents answer: %w", err)
		}

		for _, e := range page.Events {
			if seen != nil && !seen.Add(e.EventID, time.Now()) {
				continue
			}

			row := awsTrailRow(e.CloudTrailEvent)
			row.Update("EventId", e.EventID)
			if v, _ := row.GetString("EventName"); v == "" {
				row.Update("EventName", e.EventName)
				row.Update("EventSource", e.EventSource)
			}
			if v, _ := row.GetString("User"); v == "" {
				row.Update("User", e.Username)
			}
			var resources []interface{}
			for _, r := range e.Resources {
				resources = append(resources, rawToAny(r))
			}
			row.Update("Resources", resources)

			select {
			case <-ctx.Done():
				return false, nil
			case self.output <- row:
			}
			self.count++
			if self.arg.MaxRows > 0 && self.count >= self.arg.MaxRows {
				return false, nil
			}
		}

		if page.NextToken == "" {
			return true, nil
		}
		req["NextToken"] = page.NextToken
	}
}

type awsTrailEvent struct {
	EventTime         string          `json:"eventTime"`
	EventSource       string          `json:"eventSource"`
	EventName         string          `json:"eventName"`
	AWSRegion         string          `json:"awsRegion"`
	SourceIPAddress   string          `json:"sourceIPAddress"`
	UserAgent         string          `json:"userAgent"`
	ErrorCode         string          `json:"errorCode"`
	ErrorMessage      string          `json:"errorMessage"`
	ReadOnly          *bool           `json:"readOnly"`
	RecipientAccount  string          `json:"recipientAccountId"`
	RequestParameters json.RawMessage `json:"requestParameters"`
	ResponseElements  json.RawMessage `json:"responseElements"`
	AdditionalData    json.RawMessage `json:"additionalEventData"`
	UserIdentity      struct {
		Type           string `json:"type"`
		PrincipalID    string `json:"principalId"`
		ARN            string `json:"arn"`
		AccountID      string `json:"accountId"`
		AccessKeyID    string `json:"accessKeyId"`
		UserName       string `json:"userName"`
		InvokedBy      string `json:"invokedBy"`
		SessionContext struct {
			SessionIssuer struct {
				Type     string `json:"type"`
				ARN      string `json:"arn"`
				UserName string `json:"userName"`
			} `json:"sessionIssuer"`
			Attributes struct {
				MFAAuthenticated string `json:"mfaAuthenticated"`
			} `json:"attributes"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
}

// awsUserName gives one readable name for any CloudTrail identity.
func awsUserName(e *awsTrailEvent) string {
	id := e.UserIdentity
	switch id.Type {
	case "Root":
		return "root"
	case "IAMUser":
		if id.UserName != "" {
			return id.UserName
		}
	case "AssumedRole":
		// arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
		if idx := strings.Index(id.ARN, ":assumed-role/"); idx >= 0 {
			return id.ARN[idx+len(":assumed-role/"):]
		}
	case "AWSService":
		return id.InvokedBy
	}
	if id.UserName != "" {
		return id.UserName
	}
	if idx := strings.LastIndex(id.ARN, "/"); idx >= 0 {
		return id.ARN[idx+1:]
	}
	return id.PrincipalID
}

func awsTrailRow(raw string) *ordereddict.Dict {
	e := &awsTrailEvent{}
	_ = json.Unmarshal([]byte(raw), e)

	additional := rawToAny(e.AdditionalData)
	mfa := e.UserIdentity.SessionContext.Attributes.MFAAuthenticated == "true"
	if d, ok := additional.(*ordereddict.Dict); ok {
		if v, _ := d.GetString("MFAUsed"); v == "Yes" {
			mfa = true
		}
	}

	read_only := false
	if e.ReadOnly != nil {
		read_only = *e.ReadOnly
	}

	identity := ordereddict.NewDict().
		Set("Type", e.UserIdentity.Type).
		Set("Arn", e.UserIdentity.ARN).
		Set("PrincipalId", e.UserIdentity.PrincipalID).
		Set("AccountId", e.UserIdentity.AccountID).
		Set("SessionIssuer", e.UserIdentity.SessionContext.SessionIssuer.ARN).
		Set("InvokedBy", e.UserIdentity.InvokedBy)

	return ordereddict.NewDict().
		Set("Time", e.EventTime).
		Set("Region", e.AWSRegion).
		Set("EventSource", e.EventSource).
		Set("EventName", e.EventName).
		Set("User", awsUserName(e)).
		Set("UserType", e.UserIdentity.Type).
		Set("UserArn", e.UserIdentity.ARN).
		Set("AccountId", e.RecipientAccount).
		Set("AccessKeyId", e.UserIdentity.AccessKeyID).
		Set("SourceIP", e.SourceIPAddress).
		Set("UserAgent", e.UserAgent).
		Set("ErrorCode", e.ErrorCode).
		Set("ErrorMessage", e.ErrorMessage).
		Set("ReadOnly", read_only).
		Set("MFA", mfa).
		Set("Request", awsDict(e.RequestParameters)).
		Set("Response", awsDict(e.ResponseElements)).
		Set("Additional", additional).
		Set("Identity", identity).
		Set("Resources", nil).
		Set("EventId", "")
}

// awsDict returns an empty dict rather than NULL so that queries can
// read fields without errors.
func awsDict(raw json.RawMessage) *ordereddict.Dict {
	if d, ok := rawToAny(raw).(*ordereddict.Dict); ok {
		return d
	}
	return ordereddict.NewDict()
}

// ---------------------------------------------------------------------
// aws_regions()

type awsRegionsArgs struct {
	Secret          string `vfilter:"optional,field=secret,doc=Name of an 'AWS Creds' secret."`
	AccessKeyID     string `vfilter:"optional,field=access_key_id,doc=Access key ID when no secret is used."`
	SecretAccessKey string `vfilter:"optional,field=secret_access_key,doc=Secret access key when no secret is used."`
	SessionToken    string `vfilter:"optional,field=session_token,doc=Session token for temporary keys."`
	RoleARN         string `vfilter:"optional,field=role_arn,doc=Role to assume in the customer account."`
	ExternalID      string `vfilter:"optional,field=external_id,doc=External ID that the trust policy of the role requires."`
}

type AWSRegionsPlugin struct{}

func (self AWSRegionsPlugin) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "aws_regions",
		Doc: "List the AWS regions to hunt: the regions field of the secret if set, " +
			"otherwise the regions enabled for the account (ec2:DescribeRegions), " +
			"otherwise the default commercial regions.",
		ArgType:  type_map.AddType(scope, &awsRegionsArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(acls.NETWORK).Build(),
	}
}

func (self AWSRegionsPlugin) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "aws_regions", args)()

		err := vql_subsystem.CheckAccess(scope, acls.NETWORK)
		if err != nil {
			scope.Log("aws_regions: %v", err)
			return
		}

		arg := &awsRegionsArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("aws_regions: %v", err)
			return
		}

		creds := &awsCreds{Secret: arg.Secret, AccessKeyID: arg.AccessKeyID,
			SecretAccessKey: arg.SecretAccessKey, SessionToken: arg.SessionToken,
			RoleARN: arg.RoleARN, ExternalID: arg.ExternalID}
		err = creds.resolve(ctx, scope)
		if err != nil {
			scope.Log("aws_regions: %v", err)
			return
		}

		regions := creds.RegionList()
		if len(regions) == 0 {
			regions, err = describeRegions(ctx, scope, creds)
			if err != nil {
				scope.Log("aws_regions: %v; using the default regions",
					describeAWSError(err))
				regions = awsDefaultRegions
			}
		}

		for _, r := range regions {
			select {
			case <-ctx.Done():
				return
			case output_chan <- ordereddict.NewDict().Set("Region", r):
			}
		}
	}()

	return output_chan
}

func describeRegions(ctx context.Context, scope vfilter.Scope,
	creds *awsCreds) ([]string, error) {
	client, endpoint, err := creds.client(scope, "aws_regions", "ec2", "us-east-1")
	if err != nil {
		return nil, err
	}

	data, err := awsQuery(ctx, client, endpoint, url.Values{
		"Action": {"DescribeRegions"}, "Version": {"2016-11-15"}})
	if err != nil {
		return nil, err
	}

	answer := &struct {
		Regions []string `xml:"regionInfo>item>regionName"`
	}{}
	err = xml.Unmarshal(data, answer)
	if err != nil {
		return nil, err
	}

	var res []string
	for _, r := range answer.Regions {
		if awsRegionRe.MatchString(r) {
			res = append(res, r)
		}
	}
	sort.Strings(res)
	return res, nil
}

// ---------------------------------------------------------------------
// aws_iam()

// Read-only IAM actions aws_iam() may call.
var awsIAMActions = map[string]bool{
	"GetAccountSummary":          true,
	"GetAccountPasswordPolicy":   true,
	"GetCredentialReport":        true,
	"ListUsers":                  true,
	"ListRoles":                  true,
	"ListGroups":                 true,
	"ListAccessKeys":             true,
	"ListMFADevices":             true,
	"ListAttachedUserPolicies":   true,
	"ListAttachedRolePolicies":   true,
	"ListAttachedGroupPolicies":  true,
	"ListUserPolicies":           true,
	"ListRolePolicies":           true,
	"ListGroupsForUser":          true,
	"ListOpenIDConnectProviders": true,
	"ListSAMLProviders":          true,
	"GetAccessKeyLastUsed":       true,
	"GetLoginProfile":            true,
}

type awsIAMArgs struct {
	Secret          string            `vfilter:"optional,field=secret,doc=Name of an 'AWS Creds' secret."`
	AccessKeyID     string            `vfilter:"optional,field=access_key_id,doc=Access key ID when no secret is used."`
	SecretAccessKey string            `vfilter:"optional,field=secret_access_key,doc=Secret access key when no secret is used."`
	SessionToken    string            `vfilter:"optional,field=session_token,doc=Session token for temporary keys."`
	RoleARN         string            `vfilter:"optional,field=role_arn,doc=Role to assume in the customer account."`
	ExternalID      string            `vfilter:"optional,field=external_id,doc=External ID that the trust policy of the role requires."`
	Action          string            `vfilter:"required,field=action,doc=A read-only IAM action: ListUsers, ListRoles, ListAccessKeys, GetCredentialReport, GetAccountSummary, ..."`
	Params          *ordereddict.Dict `vfilter:"optional,field=params,doc=Action parameters, e.g. dict(UserName='alice')."`
	IgnoreNotFound  bool              `vfilter:"optional,field=ignore_not_found,doc=Return no rows instead of logging an error when the entity does not exist."`
}

type AWSIAMPlugin struct{}

func (self AWSIAMPlugin) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "aws_iam",
		Doc: "Call a read-only AWS IAM action, following paging. Rows are the items " +
			"of the list in the answer; GetCredentialReport returns one row per user. " +
			"Policy documents are decoded.",
		ArgType:  type_map.AddType(scope, &awsIAMArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(acls.NETWORK).Build(),
	}
}

func (self AWSIAMPlugin) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "aws_iam", args)()

		err := vql_subsystem.CheckAccess(scope, acls.NETWORK)
		if err != nil {
			scope.Log("aws_iam: %v", err)
			return
		}

		arg := &awsIAMArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("aws_iam: %v", err)
			return
		}

		if !awsIAMActions[arg.Action] {
			var names []string
			for k := range awsIAMActions {
				names = append(names, k)
			}
			sort.Strings(names)
			scope.Log("aws_iam: %q is not an allowed read-only action (one of %v)",
				arg.Action, strings.Join(names, ", "))
			return
		}

		creds := &awsCreds{Secret: arg.Secret, AccessKeyID: arg.AccessKeyID,
			SecretAccessKey: arg.SecretAccessKey, SessionToken: arg.SessionToken,
			RoleARN: arg.RoleARN, ExternalID: arg.ExternalID}
		err = creds.resolve(ctx, scope)
		if err != nil {
			scope.Log("aws_iam: %v", err)
			return
		}

		client, endpoint, err := creds.client(scope, "aws_iam", "iam", "us-east-1")
		if err != nil {
			scope.Log("aws_iam: %v", err)
			return
		}

		emit := func(row *ordereddict.Dict) bool {
			select {
			case <-ctx.Done():
				return false
			case output_chan <- row:
				return true
			}
		}

		if arg.Action == "GetCredentialReport" {
			err = awsCredentialReport(ctx, client, endpoint, emit)
			if err != nil {
				scope.Log("aws_iam: %v", describeAWSError(err))
			}
			return
		}

		params := url.Values{"Action": {arg.Action}, "Version": {"2010-05-08"}}
		if arg.Params != nil {
			for _, k := range arg.Params.Keys() {
				v, _ := arg.Params.Get(k)
				params.Set(k, fmt.Sprintf("%v", v))
			}
		}

		for {
			data, err := awsQuery(ctx, client, endpoint, params)
			if err != nil {
				if arg.IgnoreNotFound && strings.Contains(err.Error(), "NoSuchEntity") {
					return
				}
				scope.Log("aws_iam: %v", describeAWSError(err))
				return
			}

			answer, err := xmlToDict(data)
			if err != nil {
				scope.Log("aws_iam: invalid answer: %v", err)
				return
			}
			result, _ := answer.Get(arg.Action + "Result")
			result_dict, ok := result.(*ordereddict.Dict)
			if !ok {
				return
			}

			list, found := awsResultList(result_dict)
			if !found {
				emit(result_dict)
				return
			}
			for _, item := range list {
				d, ok := item.(*ordereddict.Dict)
				if !ok {
					d = ordereddict.NewDict().Set("Value", item)
				}
				if !emit(d) {
					return
				}
			}

			truncated, _ := result_dict.GetString("IsTruncated")
			marker, _ := result_dict.GetString("Marker")
			if truncated != "true" || marker == "" {
				return
			}
			params.Set("Marker", marker)
		}
	}()

	return output_chan
}

// awsResultList finds the list in a Query API result.
func awsResultList(result *ordereddict.Dict) ([]interface{}, bool) {
	for _, k := range result.Keys() {
		v, _ := result.Get(k)
		if list, ok := v.([]interface{}); ok {
			return list, true
		}
	}
	// An empty list is an empty element; list answers always say
	// whether they are truncated.
	if _, pres := result.Get("IsTruncated"); pres {
		return nil, true
	}
	return nil, false
}

func awsCredentialReport(ctx context.Context, client *apiClient, endpoint string,
	emit func(*ordereddict.Dict) bool) error {

	// Generating the report takes a few seconds.
	for attempt := 0; ; attempt++ {
		data, err := awsQuery(ctx, client, endpoint, url.Values{
			"Action": {"GenerateCredentialReport"}, "Version": {"2010-05-08"}})
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("COMPLETE")) {
			break
		}
		if attempt >= 30 {
			return fmt.Errorf("the credential report was not ready after %d tries", attempt)
		}
		if !client.sleep(ctx, 2*time.Second) {
			return ctx.Err()
		}
	}

	data, err := awsQuery(ctx, client, endpoint, url.Values{
		"Action": {"GetCredentialReport"}, "Version": {"2010-05-08"}})
	if err != nil {
		return err
	}

	answer := &struct {
		Content string `xml:"GetCredentialReportResult>Content"`
	}{}
	err = xml.Unmarshal(data, answer)
	if err != nil {
		return err
	}
	content, err := base64.StdEncoding.DecodeString(strings.TrimSpace(answer.Content))
	if err != nil {
		return fmt.Errorf("invalid credential report: %w", err)
	}

	reader := csv.NewReader(bytes.NewReader(content))
	header, err := reader.Read()
	if err != nil {
		return err
	}
	for {
		record, err := reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		row := ordereddict.NewDict()
		for i, name := range header {
			if i < len(record) {
				row.Set(name, record[i])
			}
		}
		if !emit(row) {
			return nil
		}
	}
}

// xmlToDict turns an AWS Query API answer into dicts: elements whose
// children are all <member> or <item> become lists, leaves become
// strings, and URL-encoded policy documents are decoded.
func xmlToDict(data []byte) (*ordereddict.Dict, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))

	type node struct {
		name     string
		children []*node
		text     strings.Builder
	}

	root := &node{}
	stack := []*node{root}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := token.(type) {
		case xml.StartElement:
			n := &node{name: t.Name.Local}
			parent := stack[len(stack)-1]
			parent.children = append(parent.children, n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			stack[len(stack)-1].text.Write(t)
		}
	}

	var convert func(n *node) interface{}
	convert = func(n *node) interface{} {
		if len(n.children) == 0 {
			text := strings.TrimSpace(n.text.String())
			if strings.HasSuffix(n.name, "PolicyDocument") {
				if decoded, err := url.QueryUnescape(text); err == nil {
					if d, err := toDict([]byte(decoded)); err == nil {
						return d
					}
					return decoded
				}
			}
			return text
		}

		is_list := true
		for _, c := range n.children {
			if c.name != "member" && c.name != "item" {
				is_list = false
				break
			}
		}
		if is_list {
			list := []interface{}{}
			for _, c := range n.children {
				list = append(list, convert(c))
			}
			return list
		}

		d := ordereddict.NewDict()
		for _, c := range n.children {
			d.Set(c.name, convert(c))
		}
		return d
	}

	if len(root.children) != 1 {
		return nil, fmt.Errorf("expected one root element")
	}
	res, ok := convert(root.children[0]).(*ordereddict.Dict)
	if !ok {
		return ordereddict.NewDict(), nil
	}
	return res, nil
}

func init() {
	vql_subsystem.RegisterPlugin(&AWSCloudTrailPlugin{})
	vql_subsystem.RegisterPlugin(&AWSRegionsPlugin{})
	vql_subsystem.RegisterPlugin(&AWSIAMPlugin{})
}
