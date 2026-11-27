# Okta breach hunting

Atlantiraptor hunts a customer's Okta organisation from the server, alongside the endpoint
hunts: sign-ins, password spraying, MFA push bombing, stolen session cookies, help-desk
MFA resets, admin changes and backdoors such as rogue identity providers. Everything is
read-only; nothing in the organisation is changed.

| | |
|---|---|
| Code | `vql/server/cloud` (`okta_logs()`, `okta_api()`) |
| Artifacts | `artifacts/definitions/Cloud/Okta/` |
| Credential | secret type **Okta Creds** (`org_url`, `api_token`) |
| Tests | `go test ./vql/server/cloud/` runs every hunt against recorded-shape Okta API answers in `vql/server/cloud/fixtures/okta` |

## What it finds

Every hunt returns the same columns as the other cloud hunts, `Time, Severity,
Detection, User, IPAddress, Location, Device, Details`.

| Artifact | Finds |
|---|---|
| `Cloud.Okta.SignIns` | sign-in from a new country, impossible travel, sign-in through an anonymising proxy or Tor, high-risk sign-ins that succeeded, ThreatInsight, users reporting suspicious activity, Identity Threat Protection detections |
| `Cloud.Okta.PasswordSpray` | password spraying and brute force, critical when a guessing address then signs in |
| `Cloud.Okta.MFAFatigue` | bursts of MFA push prompts, critical when the user finally approves one |
| `Cloud.Okta.SessionHijack` | one session used from several countries, or from another browser and address (stolen session cookie); critical when it reached the Admin Console |
| `Cloud.Okta.FactorChanges` | MFA factors removed or reset, admin password resets; critical when a reset by someone else is followed by a new factor (help-desk social engineering) |
| `Cloud.Okta.AdminChanges` | identity providers added, admin roles granted, API tokens created, policies, rules, authenticators and log streams turned off, Okta support access, network zones changed |
| `Cloud.Okta.Persistence` | identity providers and API tokens configured now, of any age |
| `Cloud.Okta.CompromiseAssessment` | all of the above in one collection |
| `Cloud.Okta.Monitor` | server event: collects the whole System Log continuously and raises alerts |

Shared single-event rules live in `Cloud.Okta.Rules` and are used both by the hunts and
by the monitor.

Okta keeps the System Log for 90 days. Start `Cloud.Okta.Monitor` for each customer on
day one to keep it longer. The monitor also keeps the API token in use: Okta revokes a
token that has not been used for 30 days.

## Setting up access

### Per customer

1. In the customer's Okta Admin Console, a super administrator creates a dedicated
   service user (for example `atlantiraptor@customer.com`) and assigns it the
   **Read-only Administrator** role under **Security > Administrators**.
   `Cloud.Okta.Persistence` lists API tokens only for a **Super Administrator**; without
   that role it logs a 403 and lists identity providers only.
2. Signed in as that user, open **Security > API > Tokens > Create token**, name it
   "Atlantiraptor", and copy the value; it is shown once. An API token acts with the
   rights of the user who created it, which is why that user is read-only.
3. Optionally restrict the token to Atlant's server address under **Token network
   restrictions**.
4. In Atlantiraptor, **Secrets > Okta Creds > Add**: name it after the customer, set
   `org_url` to the `https://<name>.okta.com` address of the organisation and paste the token
   into `api_token`. Grant the secret to the users who run the hunts, and to the user
   who configures `Cloud.Okta.Monitor`.
5. Run `Cloud.Okta.CompromiseAssessment` with `OktaSecret` set to the secret's name, and
   add `Cloud.Okta.Monitor` under Server Events.

`org_url` must be on a domain Okta owns (`okta.com`, `okta-emea.com`, `oktapreview.com`,
`okta-gov.com`, `okta.mil`), and the token is only ever sent to that host, never to a
redirect or to a paging link elsewhere. A custom sign-in domain such as
`login.customer.com` is refused; use the `<name>.okta.com` address, which every
organisation keeps.

If a hunt logs HTTP 401, the token was revoked or expired after 30 days unused; create a
new one. HTTP 403 means the user who created the token lacks the role in step 1.

## VQL

```
SELECT * FROM okta_logs(secret="example", start=now() - 86400,
    filter='eventType eq "user.session.start" and outcome.result eq "FAILURE"')

SELECT * FROM okta_api(secret="example", path="/api/v1/idps")
```

`okta_logs()` returns one row per System Log event with `Time, EventType,
DisplayMessage, OktaSeverity, Result, Reason, Actor, ActorName, ActorType, ActorId,
Target, Targets, IPAddress, City, Country, Location, Lat, Lon, UserAgent, Browser, OS,
Device, Zone, SessionId, CredentialType, CredentialProvider, Provider, IsProxy, ASN,
ASOrg, ISP, Domain, DebugData, TransactionId, UUID`. With `follow=TRUE` it keeps polling
with an overlap and drops repeats by `UUID`. `okta_api()` only issues GET requests under
`/api/v1/` and follows `Link` paging. Both wait out the Okta rate limits
(`X-Rate-Limit-Reset`) and retry 5xx answers.
