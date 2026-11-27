---
title: What is Atlantiraptor?
description: What Atlantiraptor does, how its parts fit together, and where it comes from.
---

Atlantiraptor is a digital forensics and incident response (DFIR) and
threat hunting platform. It answers questions such as:

- Which of our 3,000 laptops ran `rclone.exe` in the last week?
- Who connected to this IP address, and from which process?
- What persistence does this suspicious server have, and when was it added?
- Did anyone in our Microsoft 365 tenant sign in from two countries within
  an hour, or add a forwarding rule to their mailbox?
- Collect the event logs, prefetch files and browser history from these
  five machines now, and package them for the investigation.

It does this with a lightweight agent on every endpoint, a central server
with a web console, and a query language (VQL) that describes what to
collect and how to analyse it.

## How it works

```text
   Endpoints (Windows, Linux, macOS)                Atlantiraptor server
 ┌──────────────────────────────┐   HTTPS (TLS)   ┌───────────────────────────┐
 │ Agent  ── runs VQL queries ──┼───────────────▶ │ Frontend: talks to agents │
 │        ◀─ receives work ─────┼─────────────────┤ Datastore: results, files │
 └──────────────────────────────┘                 │ Web console and REST API  │
                                                  │ Server artifacts (cloud,  │
   Analysts ── browser ─────────────────────────▶ │ alerts, integrations)     │
   SIEM/SOAR ── REST API ───────────────────────▶ └───────────────────────────┘
```

- **The agent** (also called the client) is the same Atlantiraptor program
  running as a service. It keeps a connection to the server, receives
  queries, runs them locally and streams back the rows and any files they
  upload. It does nothing on its own initiative except the monitoring
  queries the server asks it to keep running.
- **The server** accepts agent connections (the *frontend*, port 8000 by
  default), stores results in its datastore, and serves the web console and
  APIs (port 8889 by default). It also runs server-side artifacts, for
  example the cloud breach hunts, which call the Microsoft, Google, Okta and
  AWS APIs directly.
- **The console** is a web application for analysts and administrators:
  dashboards, alerts, hunts, host pages, notebooks and administration.
- **VQL** is a query language similar to SQL. Every collection, hunt,
  detection and response action is a VQL query, usually packaged as an
  [artifact](/artifacts/). This is what makes Atlantiraptor adaptable: a
  new detection or collection is a few lines of VQL, deployed in seconds,
  without changing the agent.

Agents always connect to the server, never the other way round, so
endpoints need no open ports. All communication is encrypted with TLS, and
every agent is identified by its own key.

## What you can do with it

| Task | Where to read |
|---|---|
| Find which machines saw an indicator (domain, IP, hash, file, process, user) | [Rapid hunt](/console/rapid-hunt/), [IOC sweep](/console/ioc-sweep/) |
| Triage one host: processes, network, persistence, execution history, timeline | [The host page](/clients/host/) |
| Run any artifact across the whole fleet | [Hunts](/hunts/) |
| Watch endpoints continuously and raise alerts | [Client monitoring](/clients/monitoring/), [Alerts](/console/alerts/) |
| Contain and remediate: quarantine, kill, delete, disable accounts | [Response actions](/console/response/) |
| Hunt for breaches in cloud tenants | [Cloud breach hunting](/cloud/) |
| Collect evidence from machines without an agent | [Offline collections](/offline/) |
| Analyse results, build timelines and reports | [Notebooks](/notebooks/) |
| Send alerts and results to a SIEM, chat or email | [Integrations](/server-automation/integrations/) |

## Where Atlantiraptor comes from

Atlantiraptor is a fork of [Velociraptor](https://github.com/Velocidex/velociraptor),
the open source endpoint visibility tool created by Mike Cohen and developed
by Velocidex (now part of Rapid7). Velociraptor is published under the GNU
Affero General Public License v3, and so is Atlantiraptor: its source code is
on [GitHub](https://github.com/atlantsecurity/atlantiraptor).

The agent, the server engine, VQL and most built-in artifacts come from
Velociraptor, and Atlantiraptor stays compatible with them: VQL queries and
artifacts written for Velociraptor work in Atlantiraptor. Atlant Security
adds its own features on top, described in [What's new](/whats-new/), and
publishes signed releases. Atlantiraptor is not affiliated with or endorsed
by Velocidex or Rapid7.

Some names in the product still show its origin. The program reports itself
as `velociraptor` in command line help, many VQL plugins and configuration
settings use the original names, and artifacts from the upstream project
keep their names. These are kept on purpose so that existing artifacts,
configurations and scripts keep working.

## Next steps

- Learn the vocabulary in [Key concepts](/concepts/).
- Try it on your own computer with the [Quick start](/quickstart/).
- Plan a real deployment with [Deploying Atlantiraptor](/deployment/).
