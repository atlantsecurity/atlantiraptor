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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/acls"
	"www.velocidex.com/golang/velociraptor/constants"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

// Every Okta organisation has its own address, so unlike Microsoft and
// Google the endpoint cannot be a constant. Only domains Okta owns are
// accepted, so the API token can never be sent anywhere else. Custom
// domains (login.example.com) are not accepted: use the
// <name>.okta.com address of the org, which always works for the API.
var oktaOrgHost = regexp.MustCompile(
	`^[a-z0-9][a-z0-9-]*\.(okta|oktapreview|okta-emea|okta-gov)\.com$|^[a-z0-9][a-z0-9-]*\.okta\.mil$`)

// oktaTestBase replaces the org URL in tests.
var oktaTestBase = ""

func oktaBase(org_url string) (string, error) {
	if oktaTestBase != "" {
		return oktaTestBase, nil
	}

	org_url = strings.TrimSpace(org_url)
	if !strings.Contains(org_url, "://") {
		org_url = "https://" + org_url
	}
	u, err := url.Parse(org_url)
	if err != nil {
		return "", fmt.Errorf("invalid org_url %q: %w", org_url, err)
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme != "https" || u.Port() != "" || !oktaOrgHost.MatchString(host) {
		return "", fmt.Errorf("org_url must be the https://<name>.okta.com address of the organisation "+
			"address (or okta-emea.com, oktapreview.com, okta-gov.com), not %q", org_url)
	}
	return "https://" + host, nil
}

type oktaCreds struct {
	Secret   string
	OrgURL   string
	APIToken string
}

func (self *oktaCreds) resolve(ctx context.Context, scope vfilter.Scope) error {
	err := secretsEnforced(scope, self.Secret)
	if err != nil {
		return err
	}

	if self.Secret != "" {
		s, err := getSecret(ctx, scope, constants.OKTA_CREDS, self.Secret)
		if err != nil {
			return err
		}
		s.UpdateString("org_url", &self.OrgURL)
		s.UpdateString("api_token", &self.APIToken)
	}

	if self.OrgURL == "" || self.APIToken == "" {
		return errors.New("no credentials: name an 'Okta Creds' secret with secret=, " +
			"or give org_url and api_token")
	}
	return nil
}

// oktaTransport adds the SSWS authorisation header, only for the host
// of the org.
type oktaTransport struct {
	base  http.RoundTripper
	host  string
	token string
}

func (self *oktaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != self.host {
		return nil, fmt.Errorf("refusing to send the Okta token to %v", req.URL.Host)
	}
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "SSWS "+self.token)
	return self.base.RoundTrip(req)
}

func (self *oktaCreds) client(scope vfilter.Scope, name string) (*apiClient, string, error) {
	base, err := oktaBase(self.OrgURL)
	if err != nil {
		return nil, "", err
	}
	u, _ := url.Parse(base)

	transport, err := baseTransport(scope)
	if err != nil {
		return nil, "", err
	}

	client := &http.Client{
		Transport: &oktaTransport{base: transport, host: u.Host, token: self.APIToken},
		Timeout:   5 * time.Minute,
		// Never follow redirects: a redirect would leave the org.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return newAPIClient(name, client), base, nil
}

func describeOktaError(err error) string {
	msg := err.Error()
	switch statusOf(err) {
	case 401:
		return msg + " (the API token is invalid, revoked, or expired after 30 days " +
			"unused: create a new one, see docs/cloud/okta.md)"
	case 403:
		return msg + " (the administrator who created the token lacks a role that can read this: " +
			"use a Read-only Administrator or higher)"
	}
	return msg
}

// oktaNextLink returns the rel="next" URL of a Link header, only if it
// stays on the org.
func oktaNextLink(header http.Header, base string) string {
	for _, link := range header.Values("Link") {
		for _, part := range strings.Split(link, ",") {
			part = strings.TrimSpace(part)
			if !strings.Contains(part, `rel="next"`) {
				continue
			}
			start := strings.IndexByte(part, '<')
			end := strings.IndexByte(part, '>')
			if start < 0 || end <= start {
				continue
			}
			next := part[start+1 : end]
			if !strings.HasPrefix(next, base+"/") {
				return ""
			}
			return next
		}
	}
	return ""
}

// ---------------------------------------------------------------------
// okta_logs()

type oktaLogsArgs struct {
	Secret   string      `vfilter:"optional,field=secret,doc=Name of an 'Okta Creds' secret."`
	OrgURL   string      `vfilter:"optional,field=org_url,doc=Organisation URL (https://<name>.okta.com) when no secret is used."`
	APIToken string      `vfilter:"optional,field=api_token,doc=API token when no secret is used."`
	Filter   string      `vfilter:"optional,field=filter,doc=System Log filter expression, e.g. eventType eq \"user.session.start\"."`
	Query    string      `vfilter:"optional,field=q,doc=Keyword search across events."`
	Start    vfilter.Any `vfilter:"optional,field=start,doc=Only events at or after this time (default 24 hours ago)."`
	End      vfilter.Any `vfilter:"optional,field=end,doc=Only events before this time."`
	MaxRows  int64       `vfilter:"optional,field=max_rows,doc=Stop after this many rows."`
	Follow   bool        `vfilter:"optional,field=follow,doc=Keep polling for new events. Use in event artifacts."`
	Poll     int64       `vfilter:"optional,field=poll,doc=Seconds between polls in follow mode (default 60)."`
	Overlap  int64       `vfilter:"optional,field=overlap,doc=Seconds each poll re-reads before the last one (default 300)."`
}

type OktaLogsPlugin struct{}

func (self OktaLogsPlugin) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "okta_logs",
		Doc: "Read the System Log of an Okta organisation. One row per event, with the " +
			"client, location, network and session flattened into columns.",
		ArgType:  type_map.AddType(scope, &oktaLogsArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(acls.NETWORK).Build(),
	}
}

func (self OktaLogsPlugin) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "okta_logs", args)()

		err := vql_subsystem.CheckAccess(scope, acls.NETWORK)
		if err != nil {
			scope.Log("okta_logs: %v", err)
			return
		}

		arg := &oktaLogsArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("okta_logs: %v", err)
			return
		}

		creds := &oktaCreds{Secret: arg.Secret, OrgURL: arg.OrgURL, APIToken: arg.APIToken}
		err = creds.resolve(ctx, scope)
		if err != nil {
			scope.Log("okta_logs: %v", err)
			return
		}

		start, err := optionalTime(ctx, scope, arg.Start)
		if err != nil {
			scope.Log("okta_logs: start: %v", err)
			return
		}
		end, err := optionalTime(ctx, scope, arg.End)
		if err != nil {
			scope.Log("okta_logs: end: %v", err)
			return
		}
		if start.IsZero() {
			start = time.Now().Add(-24 * time.Hour)
		}

		client, base, err := creds.client(scope, "okta_logs")
		if err != nil {
			scope.Log("okta_logs: %v", err)
			return
		}

		r := &oktaLogReader{arg: arg, client: client, base: base, output: output_chan}
		if !arg.Follow {
			if end.IsZero() {
				// A bounded query ends; an open one pages forever.
				end = time.Now()
			}
			_, err := r.read(ctx, start, end, nil)
			if err != nil {
				scope.Log("okta_logs: %v", describeOktaError(err))
			}
			return
		}

		poll := secondsOr(arg.Poll, 60)
		overlap := secondsOr(arg.Overlap, 300)
		seen := newSeenSet(overlap + 2*poll + time.Hour)
		window := &pollWindow{next: start, overlap: overlap}
		read_from := start
		for {
			now := time.Now()
			more, err := r.read(ctx, read_from, now, seen)
			if err != nil {
				scope.Log("okta_logs: %v", describeOktaError(err))
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

type oktaLogReader struct {
	arg    *oktaLogsArgs
	client *apiClient
	base   string
	output chan vfilter.Row
	count  int64
}

type oktaActor struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	AlternateID string          `json:"alternateId"`
	DisplayName string          `json:"displayName"`
	DetailEntry json.RawMessage `json:"detailEntry"`
}

type oktaEvent struct {
	UUID           string    `json:"uuid"`
	Published      string    `json:"published"`
	EventType      string    `json:"eventType"`
	Severity       string    `json:"severity"`
	DisplayMessage string    `json:"displayMessage"`
	Actor          oktaActor `json:"actor"`
	Client         struct {
		UserAgent struct {
			RawUserAgent string `json:"rawUserAgent"`
			OS           string `json:"os"`
			Browser      string `json:"browser"`
		} `json:"userAgent"`
		Zone                string `json:"zone"`
		Device              string `json:"device"`
		IPAddress           string `json:"ipAddress"`
		GeographicalContext struct {
			City        string `json:"city"`
			State       string `json:"state"`
			Country     string `json:"country"`
			Geolocation struct {
				Lat *float64 `json:"lat"`
				Lon *float64 `json:"lon"`
			} `json:"geolocation"`
		} `json:"geographicalContext"`
	} `json:"client"`
	Outcome struct {
		Result string `json:"result"`
		Reason string `json:"reason"`
	} `json:"outcome"`
	Target      []oktaActor `json:"target"`
	Transaction struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"transaction"`
	DebugContext struct {
		DebugData json.RawMessage `json:"debugData"`
	} `json:"debugContext"`
	AuthenticationContext struct {
		AuthenticationProvider string `json:"authenticationProvider"`
		CredentialProvider     string `json:"credentialProvider"`
		CredentialType         string `json:"credentialType"`
		Interface              string `json:"interface"`
		ExternalSessionID      string `json:"externalSessionId"`
		RootSessionID          string `json:"rootSessionId"`
	} `json:"authenticationContext"`
	SecurityContext struct {
		ASNumber *int64 `json:"asNumber"`
		ASOrg    string `json:"asOrg"`
		ISP      string `json:"isp"`
		Domain   string `json:"domain"`
		IsProxy  *bool  `json:"isProxy"`
	} `json:"securityContext"`
}

func (self *oktaLogReader) read(ctx context.Context, start, end time.Time,
	seen *seenSet) (bool, error) {

	params := url.Values{}
	params.Set("limit", "1000")
	params.Set("sortOrder", "ASCENDING")
	params.Set("since", start.UTC().Format("2006-01-02T15:04:05.000Z"))
	params.Set("until", end.UTC().Format("2006-01-02T15:04:05.000Z"))
	if self.arg.Filter != "" {
		params.Set("filter", self.arg.Filter)
	}
	if self.arg.Query != "" {
		params.Set("q", self.arg.Query)
	}

	next := self.base + "/api/v1/logs?" + params.Encode()
	for next != "" {
		resp, data, err := self.client.do(ctx, request{URL: next})
		if err != nil {
			return true, err
		}

		var events []json.RawMessage
		err = json.Unmarshal(data, &events)
		if err != nil {
			return true, fmt.Errorf("invalid System Log answer: %w", err)
		}
		if len(events) == 0 {
			return true, nil
		}

		for _, raw := range events {
			event := &oktaEvent{}
			if json.Unmarshal(raw, event) != nil {
				continue
			}
			if seen != nil && event.UUID != "" && !seen.Add(event.UUID, time.Now()) {
				continue
			}

			select {
			case <-ctx.Done():
				return false, nil
			case self.output <- oktaRow(event):
			}

			self.count++
			if self.arg.MaxRows > 0 && self.count >= self.arg.MaxRows {
				return false, nil
			}
		}

		next = oktaNextLink(resp.Header, self.base)
	}
	return true, nil
}

func oktaActorDict(a oktaActor) *ordereddict.Dict {
	return ordereddict.NewDict().
		Set("Id", a.ID).
		Set("Type", a.Type).
		Set("AlternateId", a.AlternateID).
		Set("DisplayName", a.DisplayName).
		Set("Detail", rawToAny(a.DetailEntry))
}

func oktaRow(e *oktaEvent) *ordereddict.Dict {
	geo := e.Client.GeographicalContext
	var location []string
	for _, p := range []string{geo.City, geo.State, geo.Country} {
		if p != "" {
			location = append(location, p)
		}
	}

	targets := []*ordereddict.Dict{}
	var target_names []string
	for _, t := range e.Target {
		targets = append(targets, oktaActorDict(t))
		name := t.AlternateID
		if name == "" || name == "unknown" {
			name = t.DisplayName
		}
		target_names = append(target_names, name)
	}

	session := e.AuthenticationContext.ExternalSessionID
	if session == "unknown" {
		session = ""
	}

	var lat, lon interface{}
	if geo.Geolocation.Lat != nil && geo.Geolocation.Lon != nil {
		lat, lon = *geo.Geolocation.Lat, *geo.Geolocation.Lon
	}
	var asn interface{}
	if e.SecurityContext.ASNumber != nil {
		asn = *e.SecurityContext.ASNumber
	}

	debug := ordereddict.NewDict()
	if d := rawToAny(e.DebugContext.DebugData); d != nil {
		debug = d.(*ordereddict.Dict)
	}

	return ordereddict.NewDict().
		Set("Time", e.Published).
		Set("EventType", e.EventType).
		Set("DisplayMessage", e.DisplayMessage).
		Set("OktaSeverity", e.Severity).
		Set("Result", e.Outcome.Result).
		Set("Reason", e.Outcome.Reason).
		Set("Actor", e.Actor.AlternateID).
		Set("ActorName", e.Actor.DisplayName).
		Set("ActorType", e.Actor.Type).
		Set("ActorId", e.Actor.ID).
		Set("Target", strings.Join(target_names, ", ")).
		Set("Targets", targets).
		Set("IPAddress", e.Client.IPAddress).
		Set("City", geo.City).
		Set("Country", geo.Country).
		Set("Location", strings.Join(location, ", ")).
		Set("Lat", lat).
		Set("Lon", lon).
		Set("UserAgent", e.Client.UserAgent.RawUserAgent).
		Set("Browser", e.Client.UserAgent.Browser).
		Set("OS", e.Client.UserAgent.OS).
		Set("Device", e.Client.Device).
		Set("Zone", e.Client.Zone).
		Set("SessionId", session).
		Set("CredentialType", e.AuthenticationContext.CredentialType).
		Set("CredentialProvider", e.AuthenticationContext.CredentialProvider).
		Set("Provider", e.AuthenticationContext.AuthenticationProvider).
		Set("IsProxy", e.SecurityContext.IsProxy != nil && *e.SecurityContext.IsProxy).
		Set("ASN", asn).
		Set("ASOrg", e.SecurityContext.ASOrg).
		Set("ISP", e.SecurityContext.ISP).
		Set("Domain", e.SecurityContext.Domain).
		Set("DebugData", debug).
		Set("TransactionId", e.Transaction.ID).
		Set("UUID", e.UUID)
}

// ---------------------------------------------------------------------
// okta_api()

type oktaAPIArgs struct {
	Secret         string            `vfilter:"optional,field=secret,doc=Name of an 'Okta Creds' secret."`
	OrgURL         string            `vfilter:"optional,field=org_url,doc=Organisation URL (https://<name>.okta.com) when no secret is used."`
	APIToken       string            `vfilter:"optional,field=api_token,doc=API token when no secret is used."`
	Path           string            `vfilter:"required,field=path,doc=API path under /api/v1/, e.g. /api/v1/users or /api/v1/idps."`
	Params         *ordereddict.Dict `vfilter:"optional,field=params,doc=Query parameters."`
	MaxRows        int64             `vfilter:"optional,field=max_rows,doc=Stop after this many rows."`
	IgnoreNotFound bool              `vfilter:"optional,field=ignore_not_found,doc=Return no rows instead of logging an error for 404 answers."`
}

type OktaAPIPlugin struct{}

func (self OktaAPIPlugin) Info(scope vfilter.Scope,
	type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "okta_api",
		Doc: "Read from the management API of an Okta organisation (GET only), " +
			"following Link paging. Rows are the items of a list answer.",
		ArgType:  type_map.AddType(scope, &oktaAPIArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(acls.NETWORK).Build(),
	}
}

func (self OktaAPIPlugin) Call(ctx context.Context,
	scope vfilter.Scope, args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "okta_api", args)()

		err := vql_subsystem.CheckAccess(scope, acls.NETWORK)
		if err != nil {
			scope.Log("okta_api: %v", err)
			return
		}

		arg := &oktaAPIArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("okta_api: %v", err)
			return
		}

		if !strings.HasPrefix(arg.Path, "/api/v1/") || strings.Contains(arg.Path, "..") ||
			strings.Contains(arg.Path, "//") || strings.ContainsAny(arg.Path, "?#") {
			scope.Log("okta_api: path must start with /api/v1/, not %q", arg.Path)
			return
		}

		creds := &oktaCreds{Secret: arg.Secret, OrgURL: arg.OrgURL, APIToken: arg.APIToken}
		err = creds.resolve(ctx, scope)
		if err != nil {
			scope.Log("okta_api: %v", err)
			return
		}

		client, base, err := creds.client(scope, "okta_api")
		if err != nil {
			scope.Log("okta_api: %v", err)
			return
		}

		params := url.Values{}
		if arg.Params != nil {
			for _, k := range arg.Params.Keys() {
				v, _ := arg.Params.Get(k)
				params.Set(k, fmt.Sprintf("%v", v))
			}
		}

		next := base + arg.Path
		if len(params) > 0 {
			next += "?" + params.Encode()
		}

		var count int64
		for next != "" {
			resp, data, err := client.do(ctx, request{URL: next})
			if err != nil {
				if arg.IgnoreNotFound && statusOf(err) == 404 {
					return
				}
				scope.Log("okta_api: %v", describeOktaError(err))
				return
			}

			trimmed := strings.TrimSpace(string(data))
			if !strings.HasPrefix(trimmed, "[") {
				item, err := toDict(data)
				if err != nil {
					scope.Log("okta_api: invalid answer: %v", err)
					return
				}
				select {
				case <-ctx.Done():
				case output_chan <- item:
				}
				return
			}

			var items []json.RawMessage
			err = json.Unmarshal(data, &items)
			if err != nil {
				scope.Log("okta_api: invalid answer: %v", err)
				return
			}

			for _, raw := range items {
				item, err := toDict(raw)
				if err != nil {
					continue
				}
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

			next = oktaNextLink(resp.Header, base)
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&OktaLogsPlugin{})
	vql_subsystem.RegisterPlugin(&OktaAPIPlugin{})
}
