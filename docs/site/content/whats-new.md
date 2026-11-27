---
title: What's new in Atlantiraptor
description: Features Atlantiraptor adds to the Velociraptor engine it is based on.
---

Atlantiraptor keeps the Velociraptor engine, agent, VQL and artifacts, and
adds the features below. The current release is **1.0.3**; every release
is listed on the [GitHub releases page](https://github.com/atlantsecurity/atlantiraptor/releases).

## A console built for investigations

- **A redesigned console** with a light theme (and a dark one), a sidebar
  grouped by task (Investigate, Client, Server, Admin), and layouts that
  work on a phone. See [Tour of the console](/console/).
- **Command palette** (<kbd>Ctrl</kbd>+<kbd>K</kbd>): jump to any page,
  client, hunt, case or notebook, or paste an IP address, domain, hash or
  path and hunt for it at once.
- **Dashboard** with connected clients, running hunts, failed hunt
  collections, server health and the alert queue.
  See [Dashboard](/console/dashboard/).
- **Pivot from any value**: click a user, process, IP address, domain,
  hash or path in any results table to hunt for it, sweep for it, filter
  by it, add it to a case or look it up on VirusTotal.

## Investigate faster

- **Rapid hunt**: paste a website, IP address, file hash, file name,
  program or user name, and every machine checks itself and answers
  within seconds. See [Rapid hunt](/console/rapid-hunt/).
- **IOC sweep**: paste a list of indicators and hunt for all of them in one
  hunt, with hits raised as alerts. MISP indicators can be imported. See
  [IOC sweep](/console/ioc-sweep/).
- **Alert queue** with statuses (new, acknowledged, closed, false
  positive), suppression rules, one-click full triage and response from the
  alert. See [Alerts](/console/alerts/).
- **One-click host triage**: the host page collects processes, network
  connections, persistence, users and execution history in one go, flags
  what deserves a look, and builds an activity timeline.
  See [The host page](/clients/host/).
- **Remote shell** in the console, with every command recorded as a
  collection. See [Remote shell](/clients/shell/).
- **Cases** that track an investigation from first alert to closure, with
  linked hosts, hunts, indicators and a timeline of notes.
  See [Cases](/console/cases/).
- **AI triage** summaries of alerts, collections and cases from Claude,
  OpenAI or DeepSeek, using your own API key. See [AI triage](/console/ai-triage/).

## Hunting

- **Hunts stop after one hour** unless you choose **Run until stopped**,
  so a quick question doesn't keep running for a week. See [Hunts](/hunts/).
- **New hunt filters** by platform, cloud service, artifact type and
  source, so the right artifact is easy to find.
- **Cloud breach hunting** for Microsoft 365 and Entra ID, Google
  Workspace, Okta and AWS, read-only, with every hunt returning the same
  findings columns. See [Cloud breach hunting](/cloud/).
- **Premium hunt feeds**: with a licence key, the server fetches hunt packs
  written and maintained by Atlant Security, verified by signature, ready to
  run in one click. See [Hunt feeds](/hunts/feeds/).

## Respond safely

- **Response actions** for the fleet: network quarantine, DNS sinkhole,
  kill process, delete file, remove scheduled tasks or services, disable
  local accounts and uninstall the agent, with dry runs and an audit trail.
- **Four-eyes approval**: optionally require a second person to approve
  live response actions. See [Response actions](/console/response/).
- **Fleet health**: agents that went quiet, agents running old versions,
  and collections that keep failing, with agent upgrades from the same
  page. See [Fleet health](/console/fleet-health/).

## Administration and security

- **Signed automatic updates**: Windows servers check the GitHub releases
  of Atlantiraptor (weekly by default), verify the Authenticode signature
  and checksum, and install new versions themselves.
  See [Updating Atlantiraptor](/deployment/updates/).
- **Two-factor sign in** with authenticator apps and recovery codes, a
  policy for who must use it, and an option to remember a trusted IP
  address for a number of days. See [Authentication](/deployment/authentication/#two-factor-sign-in).
- **Network access lists** for the console and API.
  See [Network access](/deployment/network-access/).
- **Simpler roles**: reader, analyst, investigator, hunter, responder and
  administrator, plus **groups** of users. See [Users and roles](/users/).
- **Integration REST API** with API keys, roles, IP restrictions and a
  guided "Connect SIEM" setup, alongside the original gRPC API.
  See [API keys and SIEM integration](/server-automation/api-keys/).
- **Integrations page**: send alerts to Splunk, Elasticsearch/OpenSearch,
  Slack, Teams, Discord or any webhook, and email; import MISP indicators.
  See [Integrations](/server-automation/integrations/).
- **Signed Windows installer (MSI)** for the agent, for silent deployment
  with Intune or Group Policy. See [Deploying agents](/deployment/clients/).
