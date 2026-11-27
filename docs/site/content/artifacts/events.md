---
title: Event artifacts
description: Write Atlantiraptor CLIENT_EVENT and SERVER_EVENT artifacts that monitor endpoints and the server continuously and raise alerts.
---

An **event artifact** runs without end. Its query uses an *event plugin*,
which waits for something to happen and emits a row when it does. Rows are
sent to the server in batches and stored per client and per day; see
[Client monitoring](/clients/monitoring/) for how to run them.

## A client event artifact

```yaml
name: Custom.Windows.Events.NewServices
description: New services, from the System event log (event 7045).
type: CLIENT_EVENT

sources:
  - precondition: SELECT OS FROM info() WHERE OS = 'windows'
    query: |
      SELECT System.TimeCreated.SystemTime AS Timestamp,
             EventData.ServiceName AS ServiceName,
             EventData.ImagePath AS ImagePath,
             System.Security.UserID AS UserSID
      FROM watch_evtx(filename="C:/Windows/System32/Winevt/Logs/System.evtx")
      WHERE System.EventID.Value = 7045
```

## Event plugins

| Plugin | Emits a row for |
|---|---|
| `watch_evtx()` | Each new record in a Windows event log |
| `watch_etw()` | Each event from an ETW provider (process, DNS, file, registry, network…) |
| `wmi_events()` | Each matching WMI event |
| `watch_usn()` | Each NTFS USN journal entry (file changes) |
| `watch_syslog()`, `watch_journald()`, `watch_auditd()` | New Linux log lines, journal entries or audit events |
| `ebpf_events()` | Linux kernel events through eBPF |
| `clock()` | Every `period` seconds; combine with a normal query to poll |
| `diff()` | Rows added or removed between runs of a query: for example new listening ports or new autoruns |
| `watch_monitoring()` | (Server) rows arriving from other event artifacts |

Polling with `clock()` and `diff()` turns any one-off query into a monitor:

```sql
SELECT * FROM diff(
    query={ SELECT Name, OSPath FROM Artifact.Windows.Sys.StartupItems() },
    key="Name", period=3600)
WHERE Diff = "added"
```

## Raising alerts

Call `alert()` in an event artifact to put a row into the console's
[alert queue](/console/alerts/), in addition to storing it:

```sql
SELECT *, alert(name="New service: " + ServiceName,
                level="high",
                rule="New service",
                description="A service was installed.",
                dedup=3600,
                ServiceName=ServiceName, ImagePath=ImagePath) AS _Alert
FROM ...
```

The console reads `level` as the alert's severity (`critical`, `high`,
`medium`, `low` or `info`; anything else counts as medium), and `rule`, `description` and `source` for its title
and details; any other arguments appear as the alert's details. `dedup`
suppresses repeats of the same alert for that many seconds.

## Server event artifacts

`SERVER_EVENT` artifacts run on the server, usually watching other event
queues with `watch_monitoring()`. They are how automation works: forward
every alert to a SIEM, post-process every finished collection, label new
clients. See [Event queries](/vql/events/) and
[Server automation](/server-automation/).

```sql
SELECT * FROM watch_monitoring(artifact="System.Flow.Completion")
WHERE Flow.artifacts_with_results =~ "Windows.KapeFiles"
```

## Keeping them light

Event artifacts run on every targeted machine all the time:

- filter on the client, so only interesting rows are sent,
- prefer event sources (ETW, event logs) to polling, and poll slowly when
  you must,
- send only the fields you need,
- try a new monitor on a label of a few machines first, and watch
  `Generic.Client.Stats`.

Rows are batched on the client and sent at most every 60 seconds or so
(`Client.default_max_wait`), so expect that delay before they appear on
the server.
