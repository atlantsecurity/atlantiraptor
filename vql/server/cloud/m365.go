package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/utils"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/velociraptor/vql/functions"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

// Endpoints of the Microsoft commercial cloud. Variables so tests can
// point them at a local server; nothing at run time changes them, so a
// query can never send a tenant's token anywhere else.
var (
	m365LoginBase  = "https://login.microsoftonline.com"
	m365GraphBase  = "https://graph.microsoft.com"
	m365ManageBase = "https://manage.office.com"
)

// The Office 365 Management Activity API only serves the last 7 days,
// and each content listing may span at most 24 hours.
const (
	m365AuditMaxAge    = 7 * 24 * time.Hour
	m365AuditMaxWindow = 24 * time.Hour
)

// Fields that only some audit record types carry. Every row gets them
// (NULL when absent) so that queries can use them without
// "symbol not found" errors on the other record types.
var m365AuditCommonFields = []string{
	"CreationTime", "Operation", "Workload", "UserId", "ClientIP",
	"ObjectId", "ResultStatus", "Parameters", "OperationProperties",
	"UserAgent", "SiteUrl", "SourceFileName", "ItemType",
	"TargetUserOrGroupName", "TargetUserOrGroupType",
}

var m365ContentTypes = []string{
	"Audit.AzureActiveDirectory",
	"Audit.Exchange",
	"Audit.SharePoint",
	"Audit.General",
	"DLP.All",
}

type m365Creds struct {
	Secret       string `vfilter:"optional,field=secret,doc=Name of a 'Microsoft 365 Creds' secret holding tenant_id, client_id and client_secret."`
	TenantID     string `vfilter:"optional,field=tenant_id,doc=Tenant ID (GUID) when no secret is used."`
	ClientID     string `vfilter:"optional,field=client_id,doc=App registration client ID when no secret is used."`
	ClientSecret string `vfilter:"optional,field=client_secret,doc=App registration client secret when no secret is used."`
}

func (self *m365Creds) resolve(ctx context.Context, scope vfilter.Scope) error {
	err := secretsEnforced(scope, self.Secret)
	if err != nil {
		return err
	}

	if self.Secret != "" {
		s, err := getSecret(ctx, scope, constants.M365_CREDS, self.Secret)
		if err != nil {
			return err
		}
		s.UpdateString("tenant_id", &self.TenantID)
		s.UpdateString("client_id", &self.ClientID)
		s.UpdateString("client_secret", &self.ClientSecret)
	}

	if self.TenantID == "" || self.ClientID == "" || self.ClientSecret == "" {
		return errors.New("no credentials: name a 'Microsoft 365 Creds' secret " +
			"with secret=, or give tenant_id, client_id and client_secret")
	}

	// The tenant goes into URL paths.
	if strings.ContainsAny(self.TenantID, "/?#%\\ ") {
		return fmt.Errorf("invalid tenant_id %q", self.TenantID)
	}
	return nil
}

// client returns an API client whose requests carry a token for the
// given resource (Graph or the Management API).
func (self *m365Creds) client(scope vfilter.Scope, name, resource string) (
	*apiClient, error) {
	transport, err := baseTransport(scope)
	if err != nil {
		return nil, err
	}

	key := cacheKey("m365", m365LoginBase, self.TenantID, self.ClientID,
		self.ClientSecret, resource)
	ts := cachedTokenSource(key, func() oauth2.TokenSource {
		conf := &clientcredentials.Config{
			ClientID:     self.ClientID,
			ClientSecret: self.ClientSecret,
			TokenURL: m365LoginBase + "/" + url.PathEscape(self.TenantID) +
				"/oauth2/v2.0/token",
			Scopes:    []string{resource + "/.default"},
			AuthStyle: oauth2.AuthStyleInParams,
		}
		return conf.TokenSource(tokenContext(transport))
	})

	return newAPIClient(name, authClient(transport, ts)), nil
}

// ---------------------------------------------------------------------
// m365_graph()

// The arg parser does not see embedded structs, so each plugin repeats
// the credential fields.
type m365GraphArgs struct {
	Secret       string            `vfilter:"optional,field=secret,doc=Name of a 'Microsoft 365 Creds' secret holding tenant_id, client_id and client_secret."`
	TenantID     string            `vfilter:"optional,field=tenant_id,doc=Tenant ID (GUID) when no secret is used."`
	ClientID     string            `vfilter:"optional,field=client_id,doc=App registration client ID when no secret is used."`
	ClientSecret string            `vfilter:"optional,field=client_secret,doc=App registration client secret when no secret is used."`
	Path         string            `vfilter:"required,field=path,doc=Graph path, e.g. /auditLogs/signIns or /users."`
	Params       *ordereddict.Dict `vfilter:"optional,field=params,doc=Query parameters such as $filter, $select and $top."`
	Beta         bool              `vfilter:"optional,field=beta,doc=Use the beta endpoint instead of v1.0."`
	TimeField    string            `vfilter:"optional,field=time_field,doc=Timestamp property to filter on with start and end (e.g. createdDateTime, activityDateTime)."`
	Start        vfilter.Any       `vfilter:"optional,field=start,doc=Only items with time_field at or after this time."`
	End          vfilter.Any       `vfilter:"optional,field=end,doc=Only items with time_field before this time."`
	MaxRows      int64             `vfilter:"optional,field=max_rows,doc=Stop after this many rows (default: no limit)."`
	Follow       bool              `vfilter:"optional,field=follow,doc=Keep polling for new items (needs time_field). Use in event artifacts."`
	Poll         int64             `vfilter:"optional,field=poll,doc=Seconds between polls in follow mode (default 300)."`
	Overlap      int64             `vfilter:"optional,field=overlap,doc=Seconds each poll re-reads before the last one, for late records (default 900)."`

	IgnoreNotFound bool `vfilter:"optional,field=ignore_not_found,doc=Return no rows instead of logging an error when the object does not exist (e.g. a user without a mailbox)."`
}

type M365GraphPlugin struct{}

func (self M365GraphPlugin) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "m365_graph",
		Doc: "Read from the Microsoft Graph API of a Microsoft 365 / Entra ID " +
			"tenant (GET only), following paging. Rows are the items of the " +
			"result's value list.",
		ArgType:  type_map.AddType(scope, &m365GraphArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(acls.NETWORK).Build(),
	}
}

func (self M365GraphPlugin) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "m365_graph", args)()

		err := vql_subsystem.CheckAccess(scope, acls.NETWORK)
		if err != nil {
			scope.Log("m365_graph: %v", err)
			return
		}

		arg := &m365GraphArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("m365_graph: %v", err)
			return
		}

		creds := &m365Creds{Secret: arg.Secret, TenantID: arg.TenantID,
			ClientID: arg.ClientID, ClientSecret: arg.ClientSecret}
		err = creds.resolve(ctx, scope)
		if err != nil {
			scope.Log("m365_graph: %v", err)
			return
		}

		if !strings.HasPrefix(arg.Path, "/") || strings.Contains(arg.Path, "//") ||
			strings.Contains(arg.Path, "..") {
			scope.Log("m365_graph: path must be a Graph path such as /users, not %q",
				arg.Path)
			return
		}

		start, err := optionalTime(ctx, scope, arg.Start)
		if err != nil {
			scope.Log("m365_graph: start: %v", err)
			return
		}
		end, err := optionalTime(ctx, scope, arg.End)
		if err != nil {
			scope.Log("m365_graph: end: %v", err)
			return
		}

		if (arg.Follow || !start.IsZero() || !end.IsZero()) && arg.TimeField == "" {
			scope.Log("m365_graph: start, end and follow need time_field")
			return
		}
		if arg.TimeField != "" && !isIdentifier(arg.TimeField) {
			scope.Log("m365_graph: invalid time_field %q", arg.TimeField)
			return
		}

		client, err := creds.client(scope, "m365_graph", m365GraphBase)
		if err != nil {
			scope.Log("m365_graph: %v", err)
			return
		}

		g := &graphReader{arg: arg, client: client, scope: scope,
			output: output_chan}

		if !arg.Follow {
			_, err := g.read(ctx, start, end, nil)
			if err != nil && !(arg.IgnoreNotFound && isNotFound(err)) {
				scope.Log("m365_graph: %v", describeM365Error(err))
			}
			return
		}

		g.follow(ctx, start)
	}()

	return output_chan
}

type graphReader struct {
	arg    *m365GraphArgs
	client *apiClient
	scope  vfilter.Scope
	output chan vfilter.Row
	count  int64
}

func (self *graphReader) baseURL() string {
	version := "/v1.0"
	if self.arg.Beta {
		version = "/beta"
	}
	return m365GraphBase + version
}

// read fetches all pages for one time window. When seen is not nil, items
// whose id was already emitted are skipped. It returns false when the
// row limit was reached.
func (self *graphReader) read(ctx context.Context, start, end time.Time,
	seen *seenSet) (bool, error) {

	params := url.Values{}
	if self.arg.Params != nil {
		for _, k := range self.arg.Params.Keys() {
			v, _ := self.arg.Params.Get(k)
			params.Set(k, fmt.Sprintf("%v", v))
		}
	}

	var clauses []string
	if f := params.Get("$filter"); f != "" {
		clauses = append(clauses, "("+f+")")
	}
	if !start.IsZero() {
		clauses = append(clauses, fmt.Sprintf("%s ge %s", self.arg.TimeField,
			start.UTC().Format(time.RFC3339)))
	}
	if !end.IsZero() {
		clauses = append(clauses, fmt.Sprintf("%s lt %s", self.arg.TimeField,
			end.UTC().Format(time.RFC3339)))
	}
	if len(clauses) > 0 {
		params.Set("$filter", strings.Join(clauses, " and "))
	}

	next := self.baseURL() + self.arg.Path
	if len(params) > 0 {
		next += "?" + params.Encode()
	}

	for next != "" {
		_, data, err := self.client.do(ctx, request{URL: next,
			// Needed for $count and some advanced filters; harmless otherwise.
			Headers: map[string]string{"ConsistencyLevel": "eventual"}})
		if err != nil {
			return true, err
		}

		page := &graphPage{}
		err = json.Unmarshal(data, page)
		if err != nil {
			return true, fmt.Errorf("invalid Graph response: %w", err)
		}

		// A single object (e.g. /organization/{id}) rather than a list.
		if page.Value == nil {
			row, err := toDict(data)
			if err != nil {
				return true, err
			}
			return self.emit(ctx, row, seen), nil
		}

		for _, item := range page.Value {
			row, err := toDict(item)
			if err != nil {
				continue
			}
			if !self.emit(ctx, row, seen) {
				return false, nil
			}
		}

		next = page.NextLink
		// The next link must stay on Graph: it receives the token.
		if next != "" && !strings.HasPrefix(next, m365GraphBase+"/") {
			return true, fmt.Errorf("refusing nextLink outside Graph: %v",
				redactURL(next))
		}
	}
	return true, nil
}

func (self *graphReader) emit(ctx context.Context, row *ordereddict.Dict,
	seen *seenSet) bool {
	if seen != nil {
		id, _ := row.GetString("id")
		if id != "" && !seen.Add(id, time.Now()) {
			return true
		}
	}

	select {
	case <-ctx.Done():
		return false
	case self.output <- row:
	}

	self.count++
	return self.arg.MaxRows <= 0 || self.count < self.arg.MaxRows
}

func (self *graphReader) follow(ctx context.Context, start time.Time) {
	poll := secondsOr(self.arg.Poll, 300)
	overlap := secondsOr(self.arg.Overlap, 900)
	if start.IsZero() {
		start = time.Now().Add(-overlap)
	}

	seen := newSeenSet(overlap + 2*poll + time.Hour)
	window := &pollWindow{next: start, overlap: overlap}
	first := true

	for {
		now := time.Now()
		read_from := window.Start()
		if first {
			read_from = start
			first = false
		}

		more, err := self.read(ctx, read_from, time.Time{}, seen)
		if err != nil {
			self.scope.Log("m365_graph: %v", describeM365Error(err))
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
	}
}

type graphPage struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

// describeM365Error adds a hint for the errors customers will hit when
// setting up the connector.
func isNotFound(err error) bool {
	if statusOf(err) == 404 {
		return true
	}
	// Exchange answers 404 for users without a mailbox, but some
	// endpoints use other codes for the same thing.
	msg := err.Error()
	return strings.Contains(msg, "MailboxNotEnabledForRESTAPI") ||
		strings.Contains(msg, "ResourceNotFound") ||
		strings.Contains(msg, "ErrorItemNotFound")
}

func describeM365Error(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "RequestFromNonPremiumTenant"),
		strings.Contains(msg, "Authentication_RequestFromNonPremiumTenantOrB2CTenant"):
		return msg + " (sign-in logs through Graph need an Entra ID P1 or P2 licence in the tenant)"
	case strings.Contains(msg, "AADSTS7000215"):
		return msg + " (the client secret is wrong or expired)"
	case strings.Contains(msg, "AADSTS700016"), strings.Contains(msg, "AADSTS650051"),
		strings.Contains(msg, "AADSTS65001"):
		return msg + " (the app is not consented in this tenant: an admin must grant consent)"
	case statusOf(err) == 403:
		return msg + " (the app lacks a permission: see docs/cloud/m365.md for the list)"
	}
	return msg
}

// ---------------------------------------------------------------------
// m365_audit()

type m365AuditArgs struct {
	Secret       string      `vfilter:"optional,field=secret,doc=Name of a 'Microsoft 365 Creds' secret holding tenant_id, client_id and client_secret."`
	TenantID     string      `vfilter:"optional,field=tenant_id,doc=Tenant ID (GUID) when no secret is used."`
	ClientID     string      `vfilter:"optional,field=client_id,doc=App registration client ID when no secret is used."`
	ClientSecret string      `vfilter:"optional,field=client_secret,doc=App registration client secret when no secret is used."`
	ContentType  string      `vfilter:"required,field=content_type,doc=One of Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General, DLP.All."`
	Start        vfilter.Any `vfilter:"optional,field=start,doc=Start of the window (default 24 hours ago, at most 7 days ago)."`
	End          vfilter.Any `vfilter:"optional,field=end,doc=End of the window (default now)."`
	Follow       bool        `vfilter:"optional,field=follow,doc=Keep polling for new audit content. Use in event artifacts."`
	Poll         int64       `vfilter:"optional,field=poll,doc=Seconds between polls in follow mode (default 300)."`
	Overlap      int64       `vfilter:"optional,field=overlap,doc=Seconds each poll re-reads before the last one (default 1800)."`
}

type M365AuditPlugin struct{}

func (self M365AuditPlugin) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "m365_audit",
		Doc: "Read the Microsoft 365 unified audit log (Exchange, SharePoint, " +
			"OneDrive, Entra ID, Teams...) through the Office 365 Management " +
			"Activity API. Starts the content subscription when needed.",
		ArgType:  type_map.AddType(scope, &m365AuditArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(acls.NETWORK).Build(),
	}
}

func (self M365AuditPlugin) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "m365_audit", args)()

		err := vql_subsystem.CheckAccess(scope, acls.NETWORK)
		if err != nil {
			scope.Log("m365_audit: %v", err)
			return
		}

		arg := &m365AuditArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("m365_audit: %v", err)
			return
		}

		if !utils.InString(m365ContentTypes, arg.ContentType) {
			scope.Log("m365_audit: content_type must be one of %v",
				strings.Join(m365ContentTypes, ", "))
			return
		}

		creds := &m365Creds{Secret: arg.Secret, TenantID: arg.TenantID,
			ClientID: arg.ClientID, ClientSecret: arg.ClientSecret}
		err = creds.resolve(ctx, scope)
		if err != nil {
			scope.Log("m365_audit: %v", err)
			return
		}
		tenant := creds.TenantID

		start, err := optionalTime(ctx, scope, arg.Start)
		if err != nil {
			scope.Log("m365_audit: start: %v", err)
			return
		}
		end, err := optionalTime(ctx, scope, arg.End)
		if err != nil {
			scope.Log("m365_audit: end: %v", err)
			return
		}

		client, err := creds.client(scope, "m365_audit", m365ManageBase)
		if err != nil {
			scope.Log("m365_audit: %v", err)
			return
		}

		a := &auditReader{arg: arg, tenant: tenant, client: client, scope: scope,
			output: output_chan, seen: newSeenSet(9 * 24 * time.Hour)}

		err = a.ensureSubscription(ctx)
		if err != nil {
			scope.Log("m365_audit: %v", describeM365Error(err))
			return
		}

		now := time.Now()
		if start.IsZero() {
			start = now.Add(-24 * time.Hour)
		}

		if !arg.Follow {
			if end.IsZero() || end.After(now) {
				end = now
			}
			err := a.readRange(ctx, start, end)
			if err != nil {
				scope.Log("m365_audit: %v", describeM365Error(err))
			}
			return
		}

		a.follow(ctx, start)
	}()

	return output_chan
}

type auditReader struct {
	arg    *m365AuditArgs
	tenant string
	client *apiClient
	scope  vfilter.Scope
	output chan vfilter.Row

	// Content blobs already read.
	seen *seenSet
}

func (self *auditReader) feedURL(suffix string, params url.Values) string {
	params.Set("PublisherIdentifier", self.tenant)
	return m365ManageBase + "/api/v1.0/" + url.PathEscape(self.tenant) +
		"/activity/feed/" + suffix + "?" + params.Encode()
}

type m365Subscription struct {
	ContentType string `json:"contentType"`
	Status      string `json:"status"`
}

// ensureSubscription starts the content type's subscription if it is
// not enabled. Microsoft has no audit content for a content type from
// before its subscription started.
func (self *auditReader) ensureSubscription(ctx context.Context) error {
	_, data, err := self.client.do(ctx, request{
		URL: self.feedURL("subscriptions/list", url.Values{})})
	if err != nil {
		return err
	}

	var subs []m365Subscription
	err = json.Unmarshal(data, &subs)
	if err != nil {
		return fmt.Errorf("invalid subscriptions answer: %w", err)
	}
	for _, s := range subs {
		if s.ContentType == self.arg.ContentType &&
			strings.EqualFold(s.Status, "enabled") {
			return nil
		}
	}

	params := url.Values{}
	params.Set("contentType", self.arg.ContentType)
	_, _, err = self.client.do(ctx, request{Method: "POST",
		URL: self.feedURL("subscriptions/start", params), Body: []byte("{}")})
	if err != nil && !strings.Contains(err.Error(), "AF20024") {
		return err
	}

	self.scope.Log("m365_audit: started the %v subscription for tenant %v. "+
		"Microsoft only has audit content from now on, and the first content "+
		"can take up to 12 hours to appear.", self.arg.ContentType,
		self.tenant)
	return nil
}

type m365Content struct {
	ContentID      string `json:"contentId"`
	ContentURI     string `json:"contentUri"`
	ContentCreated string `json:"contentCreated"`
}

// readRange lists and reads all content created in [start, end), in
// windows of at most 24 hours.
func (self *auditReader) readRange(ctx context.Context, start, end time.Time) error {
	oldest := time.Now().Add(-m365AuditMaxAge).Add(time.Minute)
	if start.Before(oldest) {
		self.scope.Log("m365_audit: the Management Activity API only keeps 7 days; "+
			"reading from %v instead of %v. Run Cloud.M365.Monitor to keep a "+
			"longer history.", oldest.UTC().Format(time.RFC3339),
			start.UTC().Format(time.RFC3339))
		start = oldest
	}

	for window_start := start; window_start.Before(end); {
		window_end := window_start.Add(m365AuditMaxWindow)
		if window_end.After(end) {
			window_end = end
		}

		err := self.readWindow(ctx, window_start, window_end)
		if err != nil {
			return err
		}
		window_start = window_end
	}
	return nil
}

func (self *auditReader) readWindow(ctx context.Context, start, end time.Time) error {
	const layout = "2006-01-02T15:04:05"

	params := url.Values{}
	params.Set("contentType", self.arg.ContentType)
	params.Set("startTime", start.UTC().Format(layout))
	params.Set("endTime", end.UTC().Format(layout))
	next := self.feedURL("subscriptions/content", params)

	for next != "" {
		resp, data, err := self.client.do(ctx, request{URL: next})
		if err != nil {
			return err
		}

		var contents []m365Content
		err = json.Unmarshal(data, &contents)
		if err != nil {
			return fmt.Errorf("invalid content listing: %w", err)
		}

		for _, c := range contents {
			if !self.seen.Add(c.ContentID, time.Now()) {
				continue
			}
			err := self.readContent(ctx, c)
			if err != nil {
				// Forget it so the next poll tries again.
				self.forget(c.ContentID)
				return err
			}
		}

		next = resp.Header.Get("NextPageUri")
		if next != "" && !strings.HasPrefix(next, m365ManageBase+"/") {
			return fmt.Errorf("refusing NextPageUri outside the Management API: %v",
				redactURL(next))
		}
	}
	return nil
}

func (self *auditReader) forget(id string) {
	self.seen.mu.Lock()
	defer self.seen.mu.Unlock()
	delete(self.seen.keys, id)
}

func (self *auditReader) readContent(ctx context.Context, c m365Content) error {
	if !strings.HasPrefix(c.ContentURI, m365ManageBase+"/") {
		return fmt.Errorf("refusing contentUri outside the Management API: %v",
			redactURL(c.ContentURI))
	}

	_, data, err := self.client.do(ctx, request{URL: c.ContentURI})
	if err != nil {
		return err
	}

	var records []json.RawMessage
	err = json.Unmarshal(data, &records)
	if err != nil {
		return fmt.Errorf("invalid audit content: %w", err)
	}

	for _, r := range records {
		row, err := toDict(r)
		if err != nil {
			continue
		}
		for _, field := range m365AuditCommonFields {
			if _, pres := row.Get(field); !pres {
				row.Set(field, nil)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case self.output <- row:
		}
	}
	return nil
}

func (self *auditReader) follow(ctx context.Context, start time.Time) {
	poll := secondsOr(self.arg.Poll, 300)
	overlap := secondsOr(self.arg.Overlap, 1800)
	window := &pollWindow{next: start, overlap: overlap}
	first := true

	for {
		now := time.Now()
		read_from := window.Start()
		if first {
			read_from = start
			first = false
		}

		err := self.readRange(ctx, read_from, now)
		if err != nil {
			self.scope.Log("m365_audit: %v", describeM365Error(err))
		} else {
			window.Advance(now)
		}
		self.seen.Prune(now)

		if !sleepCtx(ctx, poll) {
			return
		}
	}
}

// ---------------------------------------------------------------------
// helpers

func optionalTime(ctx context.Context, scope vfilter.Scope,
	v vfilter.Any) (time.Time, error) {
	if v == nil || utils.IsNil(v) {
		return time.Time{}, nil
	}
	t, err := functions.TimeFromAny(ctx, scope, v)
	if err != nil {
		return time.Time{}, err
	}
	// TimeFromAny maps 0 to the epoch; treat it as unset.
	if t.Unix() <= 0 {
		return time.Time{}, nil
	}
	return t, nil
}

func secondsOr(v int64, def int64) time.Duration {
	if v <= 0 {
		v = def
	}
	return time.Duration(v) * time.Second
}

func isIdentifier(s string) bool {
	for _, c := range s {
		if !(c == '_' || c == '/' || c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return s != ""
}

func toDict(data []byte) (*ordereddict.Dict, error) {
	row := ordereddict.NewDict()
	err := row.UnmarshalJSON(data)
	if err != nil {
		return nil, err
	}
	return row, nil
}

func init() {
	vql_subsystem.RegisterPlugin(&M365GraphPlugin{})
	vql_subsystem.RegisterPlugin(&M365AuditPlugin{})
}
