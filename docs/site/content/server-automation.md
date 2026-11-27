---
title: Server automation
description: Automate Atlantiraptor with server artifacts and server event artifacts - forward alerts, react to finished collections, schedule hunts - and integrate with other tools.
---

Everything the console does, VQL on the server can do too. That makes
Atlantiraptor easy to automate: react to events as they happen, run work on
a schedule, and connect it to the rest of your security tools.

## The building blocks

| Block | Runs | Use it for |
|---|---|---|
| **Server artifacts** (`SERVER`) | Once, under **Server collections** | One-off jobs: imports, exports, reports, cloud hunts |
| **Server event artifacts** (`SERVER_EVENT`) | Continuously, under **Server events** | Reacting to events: forward alerts, post-process collections, label clients, schedule hunts |
| **Event queues** | Always | The events to react to; see [Event queries](/vql/events/#event-queues-on-the-server) |
| **Secrets** | When a query uses one | Credentials for the systems you connect to; see [Secrets](/secrets/) |
| **APIs** | When called | Letting other systems drive Atlantiraptor; see [API keys](/server-automation/api-keys/) and the [gRPC API](/server-automation/grpc-api/) |

## Common automation

### Forward alerts

The **Integrations** page turns on ready-made forwarders for Slack,
Teams, Discord and webhooks, email, Splunk and Elastic. See
[Integrations](/server-automation/integrations/) and
[Alerting](/server-automation/alerting/).

### React to finished collections

Every finished collection emits a row on `System.Flow.Completion`. A
server event artifact can follow up:

```yaml
name: Custom.Server.Automation.TriageFollowUp
type: SERVER_EVENT
sources:
  - query: |
      SELECT collect_client(client_id=ClientId,
                            artifacts="Windows.Memory.ProcessDump",
                            spec=dict(`Windows.Memory.ProcessDump`=dict(
                                ProcessRegex="rundll32")))
      FROM watch_monitoring(artifact="System.Flow.Completion")
      WHERE Flow.artifacts_with_results =~ "Windows.Detection.Yara.Process"
```

### Schedule work

`clock()` emits a row on a schedule; combine it with `hunt()` or
`collect_client()`. `Server.Monitoring.ScheduleHunt` is a worked example
that starts a hunt at a set time on chosen days.

### Keep the fleet tidy

- Label clients by what they are (see
  [Automatic labels](/clients/#automatic-labels)).
- Delete old monitoring data with `Server.Utils.DeleteMonitoringData`, and
  old collections with `Server.Utils.DeleteManyFlows` (see
  [Storage](/deployment/storage/#deleting-old-data)).
- Watch the server with `Server.Monitor.Health`.

## Writing your own

1. Write the artifact (`type: SERVER_EVENT`) under **Artifacts**, **New**.
   Name it `Custom.Server.…`.
2. Test the query in a notebook first: a notebook cell runs on the server
   with the same plugins. Use `send_event()` to inject a test event into a
   queue.
3. Add it under **Server events**, **Configure**.
4. Watch its log and results under **Server events**.

Server event artifacts run with the server's own, full permissions, and
only administrators can change **Server events**. Review them as you would
any code that runs on the server; the change is recorded in the
[audit log](/deployment/logging/#the-audit-log).

## In this section

- [Integrations](/server-automation/integrations/): SIEMs, chat, email,
  MISP, TheHive, cloud log stores.
- [API keys and the REST API](/server-automation/api-keys/): connect a
  SIEM or SOAR.
- [The gRPC API](/server-automation/grpc-api/): full programmatic access
  with VQL.
- [Alerting](/server-automation/alerting/): how alerts are raised,
  routed and forwarded.
