---
title: Client monitoring
description: Run event artifacts continuously on endpoints and the server, view their data, and target them with labels.
---

Collections and hunts answer a question once. **Monitoring** keeps asking:
event artifacts run all the time on endpoints (or on the server) and send a
row whenever something happens, such as a new process, a DNS lookup, a
Sigma rule match or a USB device. The data is stored per client and per day,
and detections among them raise [alerts](/console/alerts/).

## Client events

Open **Client events** from a host, or from the dashboard for all clients.

### Choosing what runs

Click **Configure** to see the monitoring table:

- **All clients**: artifacts every client runs.
- **Label groups**: extra artifacts that run only on clients with a label
  (for example `Windows.ETW.DNS` only on `servers`).

![Client monitoring configuration](/images/monitoring-config.webp "Configuring client monitoring: artifacts for all clients, label groups, and the event artifacts available.")

Add artifacts from the list on the right, set their parameters, and save.
Clients pick up the change within a minute. Removing an artifact stops it.

Useful built-in event artifacts:

| Artifact | Sends |
|---|---|
| `Windows.Detection.SigmaMonitor` | Sigma rule matches on Windows event logs, as alerts |
| `Generic.Detection.YaraMonitor` | YARA matches in recently changed files (checked every few minutes), as alerts |
| `Windows.Events.ProcessCreation` | Every process start (WMI) |
| `Windows.ETW.DNS` | DNS lookups (ETW) |
| `Windows.Events.ServiceCreation` | New services |
| `Windows.Detection.Usn` | File system changes matching a pattern, from the USN journal |
| `Linux.Events.SSHLogin` | SSH logins |
| `Generic.Client.Stats` | The agent's own CPU and memory use |

See the [artifact reference](/reference/artifacts/) for all `CLIENT_EVENT`
artifacts.

### Viewing the data

Pick an artifact and a time window (a day, or a range). The table shows the
rows from that window; filter, sort, pivot, and export the window as CSV or
JSON. **Classic timeline view** shows several artifacts on one timeline.

![Client events table](/images/client-events.webp "Generic.Client.Stats rows for the last 24 hours.")

If an artifact shows "not running (historical data only)", it was removed
from the monitoring table but its old data is still stored.

## Server events

**Server events** works the same way for `SERVER_EVENT` artifacts, which
run on the server: forwarding alerts to integrations, cloud tenant
monitoring, audit logs, automation. See [Server automation](/server-automation/).

## How monitoring affects endpoints

Event artifacts are designed to be light, but they all run continuously on
every targeted endpoint. Before adding one to all clients:

- try it on a label group of a few machines and watch `Generic.Client.Stats`
  and the agent's CPU,
- check how many rows it produces per day: monitoring data is the main
  consumer of server [storage](/deployment/storage/#how-much-space),
- prefer artifacts that filter on the client (detections) over ones that
  ship every event to the server.

## Data retention

Monitoring data is kept until you delete it. Use
`Server.Utils.DeleteMonitoringData` to remove data older than a date, per
artifact. See [Storage and data retention](/deployment/storage/#deleting-old-data).

## In VQL

Client monitoring data can be queried in notebooks:

```sql
SELECT * FROM source(client_id="C.1a2b3c4d5e6f7a8b",
                     artifact="Windows.Events.ProcessCreation",
                     start_time=now() - 3600)
```

and followed live on the server with `watch_monitoring()`. See
[Event queries](/vql/events/).
