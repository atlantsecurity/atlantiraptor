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
	"golang.org/x/oauth2/jwt"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/constants"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

// Google endpoints. The token URL is fixed here rather than taken from
// the service account file, so a doctored key file cannot send the
// signed assertion elsewhere.
var (
	gwsTokenURL  = "https://oauth2.googleapis.com/token"
	gwsAdminBase = "https://admin.googleapis.com"
	gwsGmailBase = "https://gmail.googleapis.com"
)

const (
	gwsReportsScope   = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
	gwsDirectoryScope = "https://www.googleapis.com/auth/admin.directory.user.readonly"
)

var gwsApplications = []string{
	"access_transparency", "admin", "calendar", "chat", "chrome", "context_aware_access",
	"data_studio", "drive", "gcp", "gplus", "groups", "groups_enterprise", "jamboard",
	"keep", "login", "meet", "mobile", "rules", "saml", "token", "user_accounts",
	"vault",
}

type gwsCreds struct {
	Secret             string
	ServiceAccountJSON string
	AdminEmail         string
}

type gwsKeyFile struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
}

func (self *gwsCreds) resolve(ctx context.Context, scope vfilter.Scope) error {
	err := secretsEnforced(scope, self.Secret)
	if err != nil {
		return err
	}

	if self.Secret != "" {
		s, err := getSecret(ctx, scope, constants.GWS_CREDS, self.Secret)
		if err != nil {
			return err
		}
		s.UpdateString("service_account_json", &self.ServiceAccountJSON)
		s.UpdateString("admin_email", &self.AdminEmail)
	}

	if self.ServiceAccountJSON == "" || self.AdminEmail == "" {
		return errors.New("no credentials: name a 'Google Workspace Creds' secret " +
			"with secret=, or give service_account_json and admin_email")
	}
	return nil
}

// client returns an API client acting as `subject` (an admin for the
// Admin SDK, or the mailbox owner for Gmail settings) with one scope.
func (self *gwsCreds) client(scope vfilter.Scope, name, subject, oauth_scope string) (
	*apiClient, error) {
	key := &gwsKeyFile{}
	err := json.Unmarshal([]byte(self.ServiceAccountJSON), key)
	if err != nil {
		return nil, fmt.Errorf("service_account_json is not a service account key file: %w", err)
	}
	if key.Type != "service_account" || key.ClientEmail == "" || key.PrivateKey == "" {
		return nil, errors.New("service_account_json must be a service account JSON key " +
			"(type service_account, with client_email and private_key)")
	}

	transport, err := baseTransport(scope)
	if err != nil {
		return nil, err
	}

	cache_key := cacheKey("gws", gwsTokenURL, key.ClientEmail, key.PrivateKey,
		subject, oauth_scope)
	ts := cachedTokenSource(cache_key, func() oauth2.TokenSource {
		conf := &jwt.Config{
			Email:        key.ClientEmail,
			PrivateKey:   []byte(key.PrivateKey),
			PrivateKeyID: key.PrivateKeyID,
			Scopes:       []string{oauth_scope},
			TokenURL:     gwsTokenURL,
			Subject:      subject,
		}
		return conf.TokenSource(tokenContext(transport))
	})

	return newAPIClient(name, authClient(transport, ts)), nil
}

func describeGWSError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unauthorized_client"):
		return msg + " (the service account's client ID is not authorised for this " +
			"scope under domain-wide delegation: see docs/cloud/google-workspace.md)"
	case strings.Contains(msg, "invalid_grant"):
		return msg + " (admin_email must be an existing admin user in the customer's " +
			"domain, and the key must not be revoked)"
	case statusOf(err) == 403:
		return msg + " (the admin user or the delegated scopes lack access)"
	}
	return msg
}

// ---------------------------------------------------------------------
// gws_reports()

type gwsReportsArgs struct {
	Secret             string      `vfilter:"optional,field=secret,doc=Name of a 'Google Workspace Creds' secret."`
	ServiceAccountJSON string      `vfilter:"optional,field=service_account_json,doc=Service account JSON key when no secret is used."`
	AdminEmail         string      `vfilter:"optional,field=admin_email,doc=Admin user to act as when no secret is used."`
	Application        string      `vfilter:"required,field=application,doc=Report application: login, admin, token, user_accounts, drive, saml, groups, mobile, ..."`
	EventName          string      `vfilter:"optional,field=event_name,doc=Only this event name."`
	UserKey            string      `vfilter:"optional,field=user_key,doc=A user's email or ID (default: all users)."`
	Filters            string      `vfilter:"optional,field=filters,doc=Reports API filters expression, e.g. doc_type==document."`
	Start              vfilter.Any `vfilter:"optional,field=start,doc=Only events at or after this time (default 24 hours ago)."`
	End                vfilter.Any `vfilter:"optional,field=end,doc=Only events before this time."`
	MaxRows            int64       `vfilter:"optional,field=max_rows,doc=Stop after this many rows."`
	Follow             bool        `vfilter:"optional,field=follow,doc=Keep polling for new events. Use in event artifacts."`
	Poll               int64       `vfilter:"optional,field=poll,doc=Seconds between polls in follow mode (default 300)."`
	Overlap            int64       `vfilter:"optional,field=overlap,doc=Seconds each poll re-reads before the last one (default 21600: Google delivers some logs hours late)."`
}

type GWSReportsPlugin struct{}

func (self GWSReportsPlugin) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "gws_reports",
		Doc: "Read Google Workspace audit events (Admin SDK Reports API). One row per " +
			"event, with its parameters as a dict.",
		ArgType:  type_map.AddType(scope, &gwsReportsArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(acls.NETWORK).Build(),
	}
}

func (self GWSReportsPlugin) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "gws_reports", args)()

		err := vql_subsystem.CheckAccess(scope, acls.NETWORK)
		if err != nil {
			scope.Log("gws_reports: %v", err)
			return
		}

		arg := &gwsReportsArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("gws_reports: %v", err)
			return
		}

		if !isIdentifier(arg.Application) {
			scope.Log("gws_reports: invalid application %q (one of %v)",
				arg.Application, strings.Join(gwsApplications, ", "))
			return
		}
		if arg.UserKey == "" {
			arg.UserKey = "all"
		}

		creds := &gwsCreds{Secret: arg.Secret,
			ServiceAccountJSON: arg.ServiceAccountJSON, AdminEmail: arg.AdminEmail}
		err = creds.resolve(ctx, scope)
		if err != nil {
			scope.Log("gws_reports: %v", err)
			return
		}

		start, err := optionalTime(ctx, scope, arg.Start)
		if err != nil {
			scope.Log("gws_reports: start: %v", err)
			return
		}
		end, err := optionalTime(ctx, scope, arg.End)
		if err != nil {
			scope.Log("gws_reports: end: %v", err)
			return
		}
		if start.IsZero() {
			start = time.Now().Add(-24 * time.Hour)
		}

		client, err := creds.client(scope, "gws_reports", creds.AdminEmail, gwsReportsScope)
		if err != nil {
			scope.Log("gws_reports: %v", err)
			return
		}

		r := &gwsReportReader{arg: arg, client: client, output: output_chan}
		if !arg.Follow {
			_, err := r.read(ctx, start, end, nil)
			if err != nil {
				scope.Log("gws_reports: %v", describeGWSError(err))
			}
			return
		}

		poll := secondsOr(arg.Poll, 300)
		overlap := secondsOr(arg.Overlap, 6*3600)
		seen := newSeenSet(overlap + 2*poll + time.Hour)
		window := &pollWindow{next: start, overlap: overlap}
		read_from := start
		for {
			now := time.Now()
			more, err := r.read(ctx, read_from, time.Time{}, seen)
			if err != nil {
				scope.Log("gws_reports: %v", describeGWSError(err))
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

type gwsReportReader struct {
	arg    *gwsReportsArgs
	client *apiClient
	output chan vfilter.Row
	count  int64
}

type gwsActivityPage struct {
	Items         []gwsActivity `json:"items"`
	NextPageToken string        `json:"nextPageToken"`
}

type gwsActivity struct {
	ID struct {
		Time            string       `json:"time"`
		UniqueQualifier gwsQualifier `json:"uniqueQualifier"`
		ApplicationName string       `json:"applicationName"`
		CustomerID      string       `json:"customerId"`
	} `json:"id"`
	Actor struct {
		Email      string `json:"email"`
		ProfileID  string `json:"profileId"`
		CallerType string `json:"callerType"`
		Key        string `json:"key"`
	} `json:"actor"`
	IPAddress   string `json:"ipAddress"`
	OwnerDomain string `json:"ownerDomain"`
	Events      []struct {
		Type       string            `json:"type"`
		Name       string            `json:"name"`
		Parameters []json.RawMessage `json:"parameters"`
	} `json:"events"`
	NetworkInfo json.RawMessage `json:"networkInfo"`
}

func (self *gwsReportReader) read(ctx context.Context, start, end time.Time,
	seen *seenSet) (bool, error) {

	params := url.Values{}
	params.Set("maxResults", "1000")
	params.Set("startTime", start.UTC().Format(time.RFC3339))
	if !end.IsZero() {
		params.Set("endTime", end.UTC().Format(time.RFC3339))
	}
	if self.arg.EventName != "" {
		params.Set("eventName", self.arg.EventName)
	}
	if self.arg.Filters != "" {
		params.Set("filters", self.arg.Filters)
	}

	base := gwsAdminBase + "/admin/reports/v1/activity/users/" +
		url.PathEscape(self.arg.UserKey) + "/applications/" +
		url.PathEscape(self.arg.Application)

	for {
		_, data, err := self.client.do(ctx, request{URL: base + "?" + params.Encode()})
		if err != nil {
			return true, err
		}

		page := &gwsActivityPage{}
		err = json.Unmarshal(data, page)
		if err != nil {
			return true, fmt.Errorf("invalid Reports API answer: %w", err)
		}

		for _, item := range page.Items {
			for idx, event := range item.Events {
				if seen != nil {
					key := fmt.Sprintf("%v/%v/%v/%d", item.ID.Time,
						item.ID.UniqueQualifier, event.Name, idx)
					if !seen.Add(key, time.Now()) {
						continue
					}
				}

				row := ordereddict.NewDict().
					Set("Time", item.ID.Time).
					Set("Application", item.ID.ApplicationName).
					Set("Actor", item.Actor.Email).
					Set("ActorType", item.Actor.CallerType).
					Set("ActorKey", item.Actor.Key).
					Set("IPAddress", item.IPAddress).
					Set("EventType", event.Type).
					Set("EventName", event.Name).
					Set("Parameters", gwsParameters(event.Parameters)).
					Set("NetworkInfo", rawToAny(item.NetworkInfo)).
					Set("OwnerDomain", item.OwnerDomain).
					Set("UniqueQualifier", string(item.ID.UniqueQualifier))

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
		}

		if page.NextPageToken == "" {
			return true, nil
		}
		params.Set("pageToken", page.NextPageToken)
	}
}

type gwsParameter struct {
	Name              string            `json:"name"`
	Value             *string           `json:"value"`
	IntValue          *json.Number      `json:"intValue"`
	BoolValue         *bool             `json:"boolValue"`
	MultiValue        []string          `json:"multiValue"`
	MultiIntValue     []json.Number     `json:"multiIntValue"`
	MessageValue      *gwsMessageValue  `json:"messageValue"`
	MultiMessageValue []gwsMessageValue `json:"multiMessageValue"`
}

type gwsMessageValue struct {
	Parameter []json.RawMessage `json:"parameter"`
}

// gwsParameters turns the API's typed parameter list into a dict of
// name to plain value.
func gwsParameters(raw []json.RawMessage) *ordereddict.Dict {
	res := ordereddict.NewDict()
	for _, r := range raw {
		p := &gwsParameter{}
		if json.Unmarshal(r, p) != nil || p.Name == "" {
			continue
		}
		switch {
		case p.Value != nil:
			res.Set(p.Name, *p.Value)
		case p.IntValue != nil:
			if i, err := p.IntValue.Int64(); err == nil {
				res.Set(p.Name, i)
			} else {
				res.Set(p.Name, p.IntValue.String())
			}
		case p.BoolValue != nil:
			res.Set(p.Name, *p.BoolValue)
		case p.MultiValue != nil:
			res.Set(p.Name, p.MultiValue)
		case p.MultiIntValue != nil:
			var ints []int64
			for _, n := range p.MultiIntValue {
				i, _ := n.Int64()
				ints = append(ints, i)
			}
			res.Set(p.Name, ints)
		case p.MessageValue != nil:
			res.Set(p.Name, gwsParameters(p.MessageValue.Parameter))
		case p.MultiMessageValue != nil:
			var list []*ordereddict.Dict
			for _, m := range p.MultiMessageValue {
				list = append(list, gwsParameters(m.Parameter))
			}
			res.Set(p.Name, list)
		default:
			res.Set(p.Name, nil)
		}
	}
	return res
}

func rawToAny(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	d, err := toDict(raw)
	if err != nil {
		return nil
	}
	return d
}

// ---------------------------------------------------------------------
// gws_api()

type gwsAPIArgs struct {
	Secret             string            `vfilter:"optional,field=secret,doc=Name of a 'Google Workspace Creds' secret."`
	ServiceAccountJSON string            `vfilter:"optional,field=service_account_json,doc=Service account JSON key when no secret is used."`
	AdminEmail         string            `vfilter:"optional,field=admin_email,doc=Admin user to act as when no secret is used."`
	Path               string            `vfilter:"required,field=path,doc=API path, e.g. /admin/directory/v1/users or /gmail/v1/users/me/settings/filters."`
	Params             *ordereddict.Dict `vfilter:"optional,field=params,doc=Query parameters."`
	Scope              string            `vfilter:"optional,field=scope,doc=OAuth scope to request (default admin.directory.user.readonly). Must be allowed for the service account under domain-wide delegation."`
	Impersonate        string            `vfilter:"optional,field=impersonate,doc=Act as this user instead of the admin (needed for Gmail settings)."`
	ItemsField         string            `vfilter:"optional,field=items_field,doc=Response field holding the list (default: the first list in the response)."`
	MaxRows            int64             `vfilter:"optional,field=max_rows,doc=Stop after this many rows."`
	IgnoreNotFound     bool              `vfilter:"optional,field=ignore_not_found,doc=Return no rows instead of logging an error for 404 answers and users without Gmail."`
}

type GWSAPIPlugin struct{}

func (self GWSAPIPlugin) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "gws_api",
		Doc: "Read from Google Workspace's Admin SDK Directory API or Gmail API " +
			"(GET only), following nextPageToken.",
		ArgType:  type_map.AddType(scope, &gwsAPIArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(acls.NETWORK).Build(),
	}
}

func (self GWSAPIPlugin) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "gws_api", args)()

		err := vql_subsystem.CheckAccess(scope, acls.NETWORK)
		if err != nil {
			scope.Log("gws_api: %v", err)
			return
		}

		arg := &gwsAPIArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("gws_api: %v", err)
			return
		}

		if !strings.HasPrefix(arg.Path, "/") || strings.Contains(arg.Path, "..") ||
			strings.Contains(arg.Path, "//") {
			scope.Log("gws_api: invalid path %q", arg.Path)
			return
		}
		base := gwsAdminBase
		if strings.HasPrefix(arg.Path, "/gmail/") {
			base = gwsGmailBase
		} else if !strings.HasPrefix(arg.Path, "/admin/") {
			scope.Log("gws_api: path must start with /admin/ or /gmail/, not %q", arg.Path)
			return
		}
		if arg.Scope == "" {
			arg.Scope = gwsDirectoryScope
		}
		if !strings.HasPrefix(arg.Scope, "https://www.googleapis.com/auth/") {
			scope.Log("gws_api: invalid scope %q", arg.Scope)
			return
		}

		creds := &gwsCreds{Secret: arg.Secret,
			ServiceAccountJSON: arg.ServiceAccountJSON, AdminEmail: arg.AdminEmail}
		err = creds.resolve(ctx, scope)
		if err != nil {
			scope.Log("gws_api: %v", err)
			return
		}

		subject := creds.AdminEmail
		if arg.Impersonate != "" {
			subject = arg.Impersonate
		}

		client, err := creds.client(scope, "gws_api", subject, arg.Scope)
		if err != nil {
			scope.Log("gws_api: %v", err)
			return
		}

		params := url.Values{}
		if arg.Params != nil {
			for _, k := range arg.Params.Keys() {
				v, _ := arg.Params.Get(k)
				params.Set(k, fmt.Sprintf("%v", v))
			}
		}

		var count int64
		for {
			u := base + arg.Path
			if len(params) > 0 {
				u += "?" + params.Encode()
			}
			_, data, err := client.do(ctx, request{URL: u})
			if err != nil {
				if arg.IgnoreNotFound && (statusOf(err) == 404 ||
					strings.Contains(err.Error(), "failedPrecondition") ||
					strings.Contains(err.Error(), "Mail service not enabled")) {
					return
				}
				scope.Log("gws_api: %v", describeGWSError(err))
				return
			}

			page, err := toDict(data)
			if err != nil {
				scope.Log("gws_api: invalid answer: %v", err)
				return
			}

			items, found := gwsItems(page, arg.ItemsField)
			if !found {
				// A single object.
				select {
				case <-ctx.Done():
				case output_chan <- page:
				}
				return
			}

			for _, item := range items {
				select {
				case <-ctx.Done():
					return
				case output_chan <- item:
				}
				count++
				if arg.MaxRows > 0 && count >= arg.MaxRows {
					return
				}
			}

			next, _ := page.GetString("nextPageToken")
			if next == "" {
				return
			}
			params.Set("pageToken", next)
		}
	}()

	return output_chan
}

// gwsItems finds the list in a Google API answer: the named field, or
// the first field holding a list.
func gwsItems(page *ordereddict.Dict, field string) ([]interface{}, bool) {
	for _, k := range page.Keys() {
		if field != "" && k != field {
			continue
		}
		v, _ := page.Get(k)
		if list, ok := v.([]interface{}); ok {
			return list, true
		}
		if field != "" {
			// The field exists but is not a list (or is empty).
			return nil, true
		}
	}
	if field != "" {
		// Google omits empty lists entirely.
		return nil, true
	}
	return nil, false
}

func init() {
	vql_subsystem.RegisterPlugin(&GWSReportsPlugin{})
	vql_subsystem.RegisterPlugin(&GWSAPIPlugin{})
}

// gwsQualifier is the uniqueQualifier of an activity. Google documents it as
// a long sent as a string; accept a bare number or any string so one odd
// value cannot fail the whole page.
type gwsQualifier string

func (self *gwsQualifier) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*self = gwsQualifier(s)
		return nil
	}
	*self = gwsQualifier(strings.TrimSpace(string(data)))
	return nil
}
