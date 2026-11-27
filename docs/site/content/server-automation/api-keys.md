---
title: API keys and the REST API
description: Connect SIEM and SOAR platforms and scripts to Atlantiraptor with API keys and the REST integration API.
---

The **REST API** lets other systems work with Atlantiraptor: a SIEM pulls
alerts, a SOAR playbook quarantines a host, a script starts a hunt. It is
served by the console's web server, at `https://<console>/api/atl/v1`,
and authenticated with **API keys**.

## Creating a key

Open **API keys** (in the sidebar; server administrators) and click **New
API key**:

- **Name**: what uses it, such as "Splunk alerts".
- **Roles**: what the key may do. A key gets exactly what a console user
  with those roles gets, checked by the server on every call. Choose the
  least that works:

  | Roles | The key can |
  |---|---|
  | `reader` | Read alerts, hosts, hunts and cases |
  | `analyst` | Also run VQL over collected data (`/query`) |
  | `investigator`, `hunter` | Also run triage collections, hunts and IOC sweeps |
  | `responder` | Also run response actions (quarantine, kill, delete) |

- **Expires**: in 30 days, 90 days, a year, or never.
- **Allowed from (optional)**: IP addresses or ranges the key may be used
  from, one per line, such as your SIEM's address. Leave it empty to allow
  any address the [API allowlist](/deployment/network-access/) permits.

**Create key** shows the key (`atl_…`) **once**. Store it in the SIEM's or
SOAR's secret store. The list shows each key's roles, expiry and allowed
addresses; **Revoke key** disables it at once.

Keys belong to the organization they were created in.

## Connect a SIEM {#connect-a-siem}

**Connect a SIEM** on the API keys page walks through connecting a SIEM in
a few steps:

1. Name the key and choose what the SIEM may do: **Full response**
   (recommended), **Triage only** or **Read only**.
2. Say where the SIEM runs (**Docker on this computer** or **Another
   machine**) and optionally its address, to lock the key to it.
3. **Create key and show settings** shows the `.env` settings to paste
   into the SIEM (`ATLANT_ATLANTIRAPTOR_URL`, `…_KEY`, `…_CA_FILE`,
   `…_CONSOLE_URL`), a button to **Download CA certificate (.pem)** so the
   SIEM can verify this server with TLS checking on, and the hosts entry
   that makes the server's certificate name resolve.
4. Restart the SIEM and **Test connection**.

## Using the API

Send the key as a bearer token:

```bash
export ATL=atl_xxxxxxxx
curl -s -H "Authorization: Bearer $ATL" https://atlantiraptor.example.com:8889/api/atl/v1/whoami
```

The server's certificate is issued by its own CA unless you configured
another one; give clients the CA certificate (from **Connect a SIEM**) rather
than turning off verification.

Main endpoints:

| Endpoint | Does |
|---|---|
| `GET /whoami` | The key's name, roles and org |
| `GET /alerts?since=…` | Alerts after a cursor; poll with the previous response's `next_since` |
| `GET /clients`, `GET /clients/{id}` | Hosts; search with the same syntax as the console |
| `POST /clients/{id}/labels` | Add or remove labels |
| `GET /actions`, `POST /actions/{id}/run` | Triage and response actions. Response actions run as a **dry run** unless `"dry_run": false`, and need a `reason` |
| `POST /collections` | Collect read-only artifacts from hosts |
| `GET /clients/{id}/flows/{flow}/results` | A collection's results |
| `POST /hunts`, `GET /hunts/{id}/results` | Start a hunt, read its results |
| `POST /rapid-hunts` | A [rapid hunt](/console/rapid-hunt/) for a hash, file, domain, process or user |
| `POST /ioc-sweeps` | An [IOC sweep](/console/ioc-sweep/) |
| `GET /cases` | Cases |
| `GET /approvals`, `POST /approvals/{id}/approve` | Two-person approval for response actions |
| `POST /query` | VQL over collected data (keys with `analyst` and without `responder`) |
| `GET /stats` | Fleet counts |

The complete, current list is in the [REST API reference](/reference/api/),
and the server serves its OpenAPI description at
`/api/atl/v1/openapi.yaml` (no key needed), which most SOAR tools can
import.

### Response actions and approvals

Response actions need the `responder` role, a `reason`, and run as a dry
run by default. When the console requires two-person approval for response
actions, a live action is created as a paused hunt that waits for an
approver (`waiting_for_approval`), exactly like one started from the
console.

### Limits and auditing

- Requests are rate limited per key; over the limit the API answers
  `429` with `Retry-After`.
- Failed authentications are throttled per address.
- Every write is recorded in the [audit log](/deployment/logging/#the-audit-log)
  as the principal `api-<key id>`.

## Examples

The API keys page has ready-to-use examples, with this server's address
filled in: curl, Splunk (scripted input), Elastic (Filebeat `httpjson`),
Microsoft Sentinel, a SOAR playbook, rapid hunts, approvals and IOC sweeps.

A minimal alert poller:

```python
import os, requests
BASE = "https://atlantiraptor.example.com:8889/api/atl/v1"
HEADERS = {"Authorization": f"Bearer {os.environ['ATL_API_KEY']}"}

since = 0
r = requests.get(f"{BASE}/alerts", params={"since": since, "limit": 1000},
                 headers=HEADERS, verify="ca.pem", timeout=30)
r.raise_for_status()
body = r.json()
for alert in body["data"]:
    print(alert)
since = body["next_since"]   # store for the next poll
```

## REST API or gRPC API?

Use the REST API for integrations: it is simple, key-based and limited to
safe, audited operations. The [gRPC API](/server-automation/grpc-api/)
gives full access with VQL and certificates, for automation that needs
everything.
