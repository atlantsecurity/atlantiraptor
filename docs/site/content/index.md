---
title: Atlantiraptor documentation
description: Documentation for Atlantiraptor, the endpoint and cloud breach hunting platform by Atlant Security.
---

Atlantiraptor lets a security team see into every computer it manages and
into its cloud tenants, ask questions of all of them at once, and act on
what it finds. An agent runs on each endpoint; a central server sends it
work, collects the answers and keeps them for investigation. Everything the
agent does is written as a query in VQL, the Velociraptor Query Language,
so the same tool covers triage, threat hunting, forensic collection,
continuous monitoring and response.

Atlantiraptor is developed by [Atlant Security](https://atlantsecurity.com).
It is based on the open source Velociraptor project and adds a redesigned
console, guided investigation workflows, cloud breach hunting, premium hunt
feeds and signed automatic updates. See [What's new in Atlantiraptor](/whats-new/).

## Where to start

<div class="cards">
<a href="/quickstart/"><b>Quick start</b><span>Run a complete server and agent on one computer in two minutes.</span></a>
<a href="/deployment/"><b>Plan a deployment</b><span>Server, certificates, sign-in and rolling out agents.</span></a>
<a href="/console/"><b>Tour the console</b><span>Dashboard, alerts, Rapid hunt, response and cases.</span></a>
<a href="/hunts/"><b>Hunt across the fleet</b><span>Ask every endpoint the same question at once.</span></a>
<a href="/cloud/"><b>Hunt cloud tenants</b><span>Microsoft 365, Google Workspace, Okta and AWS.</span></a>
<a href="/vql/"><b>Learn VQL</b><span>The query language behind every artifact.</span></a>
</div>

## Find your way around

- **[Getting started](/overview/)** explains what Atlantiraptor is, the
  words it uses and how the parts fit together.
- **[Deploying](/deployment/)** covers installing the server, securing it,
  signing users in, deploying agents and keeping everything up to date.
- **[Using the console](/console/)**, **[Endpoints](/clients/)** and
  **[Hunting](/hunts/)** are for analysts: finding hosts, collecting
  evidence, hunting and responding.
- **[Notebooks and evidence](/notebooks/)** shows how to analyse results
  and export them.
- **[Offline collections](/offline/)** covers collecting from machines
  that cannot reach the server.
- **[Artifacts](/artifacts/)** and **[VQL](/vql/)** explain how to write
  your own collections and detections.
- **[Forensics](/forensics/)** describes the forensic capabilities: file
  systems, NTFS, event logs, execution evidence, dead disk analysis.
- **[Automation and integrations](/server-automation/)** connects
  Atlantiraptor to a SIEM, SOAR, chat or email, and automates the server.
- **[Troubleshooting](/troubleshooting/)** helps when something does not
  work.
- The **Reference** section lists every [VQL plugin and function](/reference/vql/),
  [built-in artifact](/reference/artifacts/),
  [configuration setting](/reference/config/),
  [command](/reference/cli/) and [REST API endpoint](/reference/api/).
  It is generated from the source code of this version.

You can also search these pages from the console: click the **?** icon in
the top bar.

## Getting help

Customers of Atlant Security can contact support as described in
[Support](/support/). To report a security problem in Atlantiraptor, see
[Security](/security/).
