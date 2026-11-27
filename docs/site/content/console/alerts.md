---
title: Alerts
description: The Atlantiraptor alert queue - where alerts come from, statuses, suppression, triage and response from an alert.
---

Alerts tell you that something on an endpoint (or in a cloud tenant)
matched a detection. They appear in the **Alerts** panel on the
[dashboard](/console/dashboard/), newest and most severe first, and are
sent to your [integrations](/server-automation/integrations/) (SIEM, chat,
email).

## Where alerts come from

Any artifact can raise an alert with the VQL `alert()` function. Alerts
arrive in the `Server.Internal.Alerts` server event queue. Common sources:

| Source | Raises alerts for |
|---|---|
| `Windows.Detection.SigmaMonitor` | Sigma rules matching Windows event logs, live |
| `Generic.Detection.YaraMonitor` | YARA rules matching recently changed files |
| [IOC sweep](/console/ioc-sweep/) | Hits for any indicator in the sweep |
| [Cloud monitors](/cloud/) (`Cloud.M365.Monitor` and others) | Suspicious sign-ins, mailbox rules, privileged changes |
| Your own artifacts | Anything you detect with VQL (see [Alerting from VQL](/server-automation/alerting/)) |

### Turning detections on

If no detection artifacts are running, the panel offers **Enable
detections**, which adds the Sigma and YARA monitors to client monitoring
for all clients. You can fine-tune them later under **Client events**.

**Send test alert** asks a client you pick to raise a harmless test alert
(`Generic.Detection.TestAlert`). It shows up within seconds, and checks the
whole path: agent, server, dashboard and integrations.

## Working the queue

Each alert shows its severity (critical, high, medium, low, info), name,
host, time and the details the detection provided. Alerts have a
**status**, shared by everyone on the team:

| Status | Meaning |
|---|---|
| **New** | Nobody has looked at it yet. |
| **Acknowledged** | Someone is on it. The alert shows who. |
| **Closed** | Handled. |
| **False positive** | Not a real problem. Consider a suppression rule. |

![Alerts card on the dashboard](/images/alerts.webp "Open alerts on the dashboard, with severity counts, Acknowledge and Close.")

The panel opens on **Open** alerts (new and acknowledged). Filter by
severity, or show all.

The dashboard shows alerts from the last 7 days, up to 500. Older alerts
stay in `Server.Internal.Alerts`, under **Server events**.

## Acting on an alert

Change an alert's status with **Acknowledge**, **Close**, **False
positive** or **Reopen**. From the alert you can also:

- **Triage host**: starts a full triage, which collects processes, network connections, autoruns,
  services, scheduled tasks, users and recently run programs from the host
  in one collection. The results appear on its [host page](/clients/host/).
- **View source event**: the collection or event the alert came from.
- **Isolate host…**: [network quarantine](/console/response/) of the host,
  keeping its connection to the server.
- **Kill process…** or **Delete file…**: remove what the alert points at.
- **Add to case…**: link the alert to a new or existing [case](/console/cases/).
- **AI triage**: ask your configured model for a summary (see
  [AI triage](/console/ai-triage/)).
- **Suppress on this host**: hide this alert name from this host in the
  Open view, for everyone.

Response actions from an alert follow the same rules as on the Response
page: they need the right role, are recorded in the audit log, and may need
a second approver.

## Suppression rules

A suppression rule hides matching alerts from the Open view for everyone,
for example a noisy Sigma rule on a build server. The rules are listed under
the panel ("Suppression rules"), where you can remove them. Suppressed
alerts are still stored and still sent to integrations; fix the detection
itself if it is wrong everywhere.

## Getting alerts elsewhere

- Send them to Splunk, Elastic, Slack, Teams, Discord, a webhook or email:
  [Integrations](/server-automation/integrations/).
- Poll them from a SIEM or SOAR: `GET /api/atl/v1/alerts?since=` in the
  [integration API](/server-automation/api-keys/).
