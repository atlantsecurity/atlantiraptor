# Google Workspace breach hunting

Atlantiraptor hunts a customer's Google Workspace domain from the server, alongside the
endpoint hunts: sign-ins, account security changes, the Admin console audit log, OAuth
apps, Drive downloads and sharing, and Gmail forwarding. Everything is read-only; nothing
in the domain is changed.

| | |
|---|---|
| Code | `vql/server/cloud` (`gws_reports()`, `gws_api()`) |
| Artifacts | `artifacts/definitions/Cloud/GoogleWorkspace/` |
| Credential | secret type **Google Workspace Creds** (`service_account_json`, `admin_email`) |
| Tests | `go test ./vql/server/cloud/` runs every hunt against recorded-shape Google API answers in `vql/server/cloud/fixtures/gws` |

## What it finds

Every hunt returns the same columns as the Microsoft 365 hunts, `Time, Severity,
Detection, User, IPAddress, Location, Device, Details`.

| Artifact | Finds |
|---|---|
| `Cloud.GoogleWorkspace.SignIns` | sign-ins Google flagged, government-backed attack warnings, hijacked accounts, password spraying, sign-in from a new country |
| `Cloud.GoogleWorkspace.AccountChanges` | 2-Step Verification or Advanced Protection turned off, recovery email, phone or security question changed |
| `Cloud.GoogleWorkspace.AdminChanges` | admin roles granted, email monitors, domain-wide delegation granted, data exports, SSO and mail routing changes, 2SV policy weakened |
| `Cloud.GoogleWorkspace.OAuthApps` | apps users granted mail, full Drive or admin access, BEC tool watchlist |
| `Cloud.GoogleWorkspace.MailForwarding` | Gmail automatic forwarding and filters that forward outside the domain, delete or hide mail |
| `Cloud.GoogleWorkspace.MassDownload` | accounts downloading an unusual number of Drive files in an hour |
| `Cloud.GoogleWorkspace.ExternalSharing` | many files made public or shared outside the domain, sharing to personal mail |
| `Cloud.GoogleWorkspace.CompromiseAssessment` | all of the above in one collection |
| `Cloud.GoogleWorkspace.Monitor` | server event: collects the audit logs continuously and raises alerts |

Shared single-event rules live in `Cloud.GoogleWorkspace.Rules` and are used both by the
hunts and by the monitor.

Google keeps most audit events for 6 months, much longer than Microsoft, but some logs
arrive hours late. The monitor re-reads the last 6 hours on each poll and drops repeats.

## Setting up access

Google has no multi-tenant consent like Microsoft's, so each customer domain gets its own
service account, made either by the customer or by Atlant in a Google Cloud project the
customer controls.

### Per customer

1. In the Google Cloud console, pick or create a project, enable the **Admin SDK API**
   and the **Gmail API**, then **IAM & Admin > Service accounts > Create service account**
   (no roles needed). Under **Keys > Add key > JSON**, download the key file. Note the
   service account's **Unique ID** (the OAuth client ID).
2. In the Google Admin console of the customer's domain, a super admin opens
   **Security > Access and data control > API controls > Manage domain-wide delegation >
   Add new**, enters the Unique ID and these scopes, comma separated:

   ```
   https://www.googleapis.com/auth/admin.reports.audit.readonly,
   https://www.googleapis.com/auth/admin.directory.user.readonly,
   https://www.googleapis.com/auth/admin.directory.domain.readonly,
   https://www.googleapis.com/auth/gmail.settings.basic
   ```

   `gmail.settings.basic` is only needed for `Cloud.GoogleWorkspace.MailForwarding`. It
   lets the service account read (and in principle change) any user's Gmail settings;
   Atlantiraptor only reads.
3. Choose the admin user the service account acts as for the Reports and Directory APIs.
   A super admin works; a narrower choice is a dedicated user with a custom admin role
   that has **Reports** and **Users > Read** privileges.
4. In Atlantiraptor, **Secrets > Google Workspace Creds > Add**: name it after the
   customer, paste the whole JSON key into `service_account_json`, and set `admin_email`
   to the user from step 3. Grant the secret to the users who run the hunts, and to the
   user who configures `Cloud.GoogleWorkspace.Monitor`.
5. Run `Cloud.GoogleWorkspace.CompromiseAssessment` with `GWSSecret` set to the secret's
   name, and add `Cloud.GoogleWorkspace.Monitor` under Server Events.

The token endpoint is fixed in code (`oauth2.googleapis.com`), so a key file whose
`token_uri` points elsewhere cannot leak the signed assertion. Treat the JSON key like a
password: anyone holding it can read the domain's audit logs.

If a hunt logs "unauthorized_client", the scopes in step 2 don't match the service
account's Unique ID; "invalid_grant" means `admin_email` is not an existing user in the
domain or the key was revoked; a 403 means the `admin_email` user lacks the admin
privileges in step 3.

## VQL

```
SELECT * FROM gws_reports(secret="example", application="login",
    start=now() - 86400)
WHERE EventName = "login_failure"

SELECT * FROM gws_api(secret="example", path="/admin/directory/v1/users",
    params=dict(customer="my_customer"))

SELECT * FROM gws_api(secret="example", impersonate="user@example.com",
    scope="https://www.googleapis.com/auth/gmail.settings.basic",
    path="/gmail/v1/users/me/settings/filters")
```

`gws_reports()` returns one row per event, with `Time, Application, Actor, ActorType,
ActorKey, IPAddress, EventType, EventName, Parameters, NetworkInfo, OwnerDomain,
UniqueQualifier`, where `Parameters` is a dict of the event's parameters. With
`follow=TRUE` it keeps polling with an overlap and drops repeats. `gws_api()` only
issues GET requests to `admin.googleapis.com` and `gmail.googleapis.com` and follows
`nextPageToken`. Both retry throttling and 5xx answers and cache tokens per credential
and user.
