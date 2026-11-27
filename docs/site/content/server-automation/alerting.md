---
title: Alerting
description: How Atlantiraptor alerts are raised from VQL, where they go, how to forward them, and how to write your own detections.
---

An **alert** is a short, high-value message that something needs
attention. Alerts are raised by VQL, collected in one queue on the server,
shown in the console's [alert queue](/console/alerts/), and forwarded to
your [integrations](/server-automation/integrations/).

```text
Detection (client or server VQL)
  -> alert()
  -> Server.Internal.Alerts queue
  -> Alerts panel on the dashboard
  -> forwarders: webhook, email, Splunk, Elastic, your own
```

## Raising an alert

Call `alert()` anywhere in an artifact:

```sql
SELECT Name, CommandLine,
       alert(name="Encoded PowerShell",
             level="high",
             rule="Encoded PowerShell",
             description="PowerShell started with an encoded command.",
             dedup=3600,
             CommandLine=CommandLine, Pid=Pid) AS _Alert
FROM pslist()
WHERE Name =~ "powershell" AND CommandLine =~ "-enc"
```

| Argument | Meaning |
|---|---|
| `name` | The alert's name, shown as its title (required) |
| `dedup` | Don't raise the same alert again for this many seconds (default 7200) |
| `condition` | Only raise the alert if this is true |
| `level` | Severity: `critical`, `high`, `medium`, `low` or `info` (anything else counts as medium) |
| `rule`, `description`, `source` | Shown with the alert |
| any other argument | Shown in the alert's details |

Alerts raised in a client collection or a client event artifact travel to
the server with the results. The alert records the host, the artifact and
the collection it came from, so the console can link back to the source
event.

Server collections don't forward `alert()` calls. To put an alert in the
queue from the server, use `send_event(artifact="Server.Internal.Alerts",
row=…)`; `Server.Alerts.Test` does this to test forwarding.

## Detections that raise alerts

| Artifact | Kind |
|---|---|
| `Windows.Detection.SigmaMonitor` | Client event: Sigma rules on Windows event logs |
| `Generic.Detection.YaraMonitor` | Client event: YARA on recently changed files |
| `Generic.Detection.IOCSweep` | Collection or hunt: IOC sweep hits |
| `Generic.Detection.RapidHunt` | Collection or hunt: rapid hunt hits |
| `Cloud.*.Monitor` | Server event: cloud tenant detections |
| `Generic.Detection.TestAlert` | Collection: one harmless test alert |

Make your own detection a client event artifact when it should run all
the time, or a hunt when you are checking the fleet once.

## Good alerts

- Alert on things worth a person's time. Return everything else as rows
  without an alert.
- Use `dedup` so one problem doesn't raise a hundred alerts.
- Put what the analyst needs to decide into the alert's details: process,
  command line, user, file, hash.
- Set `level` honestly; integrations filter on it.

## Forwarding

Turn on forwarders on the **Integrations** page: Slack, Teams, Discord or
any webhook, email, Splunk and Elastic. Each forwards alerts at or above a
minimum severity. **Send test alert** checks the whole path.

For anything else, write a server event artifact that reads the queue:

```sql
SELECT * FROM watch_monitoring(artifact="Server.Internal.Alerts")
```

Each row has `name`, `client_id`, `artifact`, `flow_id`, `timestamp` and
`event_data` (the arguments given to `alert()`).

Older single-purpose forwarders are still available for specific events,
such as `Server.Alerts.PsExec` (email on PsExec service installs),
`Server.Alerts.WinPmem` and `Server.Alerts.Notification`.

## Reviewing past alerts

The dashboard shows the last 7 days. Older alerts stay in the queue's
storage: open **Server events**, pick `Server.Internal.Alerts` and a time
range, or query it in a notebook with `source(artifact="Server.Internal.Alerts", start_time=…)`.
