---
title: Event queries
description: VQL queries that never end - watching endpoints, following server event queues with watch_monitoring(), and building automation in Atlantiraptor.
---

Most queries end when their plugin runs out of rows. An **event query**
uses an event plugin that never runs out: it waits, and emits a row each
time something happens. Event queries are what
[event artifacts](/artifacts/events/) are made of.

```sql
-- Runs until stopped: one row per new process (Windows, WMI)
SELECT * FROM wmi_events(
  query="SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'",
  wait=5000000)
```

On the command line, an event query runs until you press Ctrl+C:

```bash
atlantiraptor query "SELECT * FROM clock(period=5)"
```

## Event queues on the server

Every event artifact, and many internal events, feed a **queue** on the
server named after the artifact. `watch_monitoring()` follows a queue and
emits each row as it arrives:

```sql
SELECT * FROM watch_monitoring(artifact="Server.Internal.Alerts")
```

Useful queues:

| Queue | Has a row for |
|---|---|
| `System.Flow.Completion` | Every finished collection, including imported offline collections |
| `System.Hunt.Creation` | Every new hunt |
| `Server.Internal.Alerts` | Every alert |
| `Server.Internal.Interrogation` | Every client whose information was updated, including new clients (rows have `ClientId`) |
| `Server.Internal.ClientDelete` | Every deleted client |
| `Server.Audit.Logs` | Every audited action |
| Any client event artifact, such as `Windows.Detection.SigmaMonitor` | Every row any client sends for it |

## Automation

Server event artifacts that watch these queues are how Atlantiraptor
automates work. Some patterns:

```sql
-- Run a follow-up collection when triage finishes
SELECT collect_client(client_id=ClientId,
                      artifacts="Windows.System.Pslist")
FROM watch_monitoring(artifact="System.Flow.Completion")
WHERE Flow.artifacts_with_results =~ "Generic.Client.Info"
```

```sql
-- Label Linux clients when their information is updated
SELECT label(client_id=ClientId, labels="linux", op="set")
FROM watch_monitoring(artifact="Server.Internal.Interrogation")
WHERE client_info(client_id=ClientId).os_info.system =~ "linux"
```

```sql
-- Mail critical alerts
SELECT mail(secret="soc-mail", to="soc@example.com",
            subject="Critical alert: " + name,
            body=format(format="%v on %v", args=[name, client_id]))
FROM watch_monitoring(artifact="Server.Internal.Alerts")
WHERE event_data.level = "critical"
```

Run them under **Server events** so they start with the server and keep
running. See [Server automation](/server-automation/).

## Sending your own events

`send_event(artifact=..., row=...)` puts a row into a queue, which is
useful to test automation or to replay an event. On clients, event
artifacts send their rows to the server's queue automatically.

## Reading past events

`watch_monitoring()` only sees new rows. For rows already stored, use
`source()` with a time range:

```sql
SELECT * FROM source(artifact="Server.Internal.Alerts",
                     start_time=now() - 86400)
```

For client events, add `client_id=`.
