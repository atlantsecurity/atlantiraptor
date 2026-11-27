# Premium hunt feeds

Atlant Security sells a subscription to a feed of hunt packs. A customer's server
administrator enters the licence key on **Hunt feeds** in the console; the server then
fetches the feed from Atlant's feed service every 6 hours, verifies Atlant's signature,
loads the packs as read-only `Atlant.Feed.*` artifacts and lists them with *New* and
*Updated* badges. Analysts start any pack as a hunt in one click.

What is sold is the **content and the service that delivers it**: the packs Atlant writes
and keeps current, and access to the feed service, which only answers for a paid licence
key. The code in this repository (the server side and the console page) is part of the
AGPL-3.0 work like everything else here.

> **Open legal question.** Whether pack content written as VQL artifacts can be licensed
> to customers under terms other than the AGPL (for example "for use on the licensee's
> own servers, no redistribution") has not been checked by a lawyer. The packs are not
> part of this repository and are loaded as data at run time, which is the usual basis
> for treating them separately, but get that confirmed before writing the subscription
> terms.

## How it works on the server

| | |
|---|---|
| Code | `services/huntfeeds` (sync, verification, repository loading), `api/atl_feeds.go`, console page `gui/.../next/pages/feeds` |
| Feed URL | `https://feeds.atlantsecurity.com/v1/feed` (`ATLANTIRAPTOR_FEED_URL` overrides it, e.g. for staging; https only) |
| State | `<datastore>/atlantiraptor_hunt_feeds.json` (mode 0600): licence key, last signed feed, when each pack was first seen |
| Sync | 30 s after start, then every 6 hours, on **Sync now**, and when the key changes; retried hourly after a network error |
| Who | Any console user who can read results sees the packs; only server administrators see or change the key |
| Audit | `hunt_feed_licence_set`, `hunt_feed_licence_removed`, `hunt_feed_activated`, `hunt_feed_rejected` |

A feed is accepted only when **all** of these hold:

1. It is signed (Ed25519) with a key listed in `services/huntfeeds/keys.go`, which is
   compiled into the binary. Nothing at run time can add a key.
2. It was issued for the licence key entered on this server (`licence.key_sha256`).
3. The subscription has not expired and the lease (`valid_until`) has not run out.
4. It is not older than the feed already installed (no replay of an old feed).
5. Every pack and artifact passes the format rules below.

When the service answers **401/403** (key unknown or revoked) or **402/410** (subscription
ended), or the lease runs out without a successful sync, the server removes the feed
artifacts at once and the page says why. Hunts that already ran keep their results. When
the subscription is renewed, the next sync brings the packs back with no action on the
customer's side.

The lease is what makes "works while the subscription is paid" hold even for a server that
stops talking to the feed service: give each manifest a lease of about two weeks, so an
outage on either side doesn't interrupt customers, and a lapsed subscription stops working
within the lease at most.

## What Atlant needs to run

1. **A feed signing key.** On a trusted machine:

   ```
   Atlantiraptor.exe feeds keygen --key-id atlant-feed-2026 --out atlant-feed-2026.key
   ```

   Store the private key file in Azure Key Vault (the feed service signs with it; nobody
   else needs it). Paste the printed public key line into `feedPublicKeys` in
   `services/huntfeeds/keys.go`, merge, and publish a release. **Until a key is in a
   release, the page says hunt feeds are not available in this build.** To rotate, add the
   new key, release, switch the service to it, and remove the old key once every feed
   signed with it has expired.

2. **The feed service** at `feeds.atlantsecurity.com` (DNS + TLS certificate). One endpoint:

   ```
   GET /v1/feed
   Authorization: Bearer <licence key>
   X-Atlantiraptor-Version: 1.0.2
   X-Atlantiraptor-Feed-Format: 1
   X-Atlantiraptor-Server: <32 hex chars, a hash of the deployment's CA certificate>
   ```

   | Answer | When |
   |---|---|
   | `200` + signed bundle (below) | key is known and paid |
   | `401` or `403` + `{"message": "..."}` | key unknown or revoked |
   | `402` or `410` + `{"message": "..."}` | subscription ended (say when, and how to renew) |
   | `429` / `5xx` | temporary; the server retries in an hour and keeps the current feed |

   The `message` is shown to the customer as is. The service needs a table of licence
   keys (key or its SHA-256, customer, plan, paid-until date, revoked flag), and should
   log the `X-Atlantiraptor-Server` values per key: several different values for one key
   means the key is being shared.

   The simplest implementation is a small web app (an Azure Function is enough) that
   looks up the key and runs, or reimplements, `feeds sign` for that customer on each
   request. Signing per request keeps the lease current.

3. **A pack repository**, private, with one YAML file per pack (see
   [`packs/`](packs/) for two examples). Check a change with:

   ```
   Atlantiraptor.exe feeds check packs/
   ```

   This parses every artifact and checks the VQL, exactly as the customer's server will.

4. **A subscription page** for the *Get a subscription* link (`SubscribeURL` in
   `services/huntfeeds/client.go`, currently `https://atlantsecurity.com/`).

## Signing a feed

```
Atlantiraptor.exe feeds sign --signing-key atlant-feed-2026.key --packs packs/ \
    --licence-key ATL-XXXX-XXXX-XXXX --licence-id L-0001 --customer "Acme Ltd" \
    --plan Premium --expires 2027-11-30 --lease-days 14 --out bundle.json

Atlantiraptor.exe feeds verify bundle.json --licence-key ATL-XXXX-XXXX-XXXX
```

(`verify` uses the keys compiled into that binary.)

## Format

The response body (the *bundle*):

```json
{ "key_id": "atlant-feed-2026",
  "payload": "<base64 of the manifest JSON>",
  "signature": "<base64 Ed25519 signature over the decoded payload bytes>" }
```

The manifest:

```json
{
  "format": 1,
  "feed": "atlant-premium",
  "issued": "2026-11-27T10:00:00Z",
  "valid_until": "2026-12-11T10:00:00Z",
  "licence": { "id": "L-0001", "customer": "Acme Ltd", "plan": "Premium",
               "expires": "2027-11-30T23:59:59Z",
               "key_sha256": "<hex SHA-256 of the licence key>" },
  "packs": [ { ...pack... } ]
}
```

A pack (the same fields as the YAML pack files):

| Field | |
|---|---|
| `id` | stable id, 2-64 of `a-z 0-9 . _ -`; new/updated tracking uses it |
| `name`, `summary`, `description` (Markdown), `changes` (Markdown) | shown on the page |
| `version` | integer ≥ 1; raise it on every change so servers show *Updated* |
| `published`, `updated` | dates |
| `severity` | `info`, `low`, `medium`, `high`, `critical` |
| `category`, `tags`, `platforms`, `references` | shown on the page; `platforms` is informational |
| `artifacts` | 1-50 artifact definitions (YAML text), each named `Atlant.Feed.*`, type `CLIENT` |
| `hunt.artifacts` | which artifacts the hunt collects (default: all of them) |
| `hunt.parameters` | `{"Atlant.Feed.X": {"Param": "value"}}`, prefilled in the launch dialog |
| `hunt.os` | `windows`, `linux`, `darwin` or empty for all clients |
| `hunt.expires_hours` | how long the hunt runs, 1-168, default 24 |
| `hunt.cpu_limit`, `hunt.timeout` | optional collection limits |

Rules the server enforces: artifact names must start with `Atlant.Feed.` (so feed content
can never replace a built-in or customer artifact), one artifact belongs to one pack only,
and only client artifacts are accepted (feed content never runs on the server itself). A
pack whose artifacts fail to load is skipped as a whole and shown with the error; the
other packs still load.

**Indicator lists** travel as the default of a `csv` artifact parameter (see
`ioc-hash-sweep.yaml`): each feed update ships the current list, and the analyst can add
to it in the launch dialog. Quote any CSV value that contains a comma, such as a glob
with `{exe,dll}`.
