---
title: Key concepts
description: The words Atlantiraptor uses - clients, artifacts, collections, hunts, monitoring, organizations and more.
---

This page defines the terms used throughout the documentation and the
console.

## Client (agent, endpoint, host)

A computer running the Atlantiraptor agent. Each client has a **client ID**
such as `C.1a2b3c4d5e6f7a8b`, created from its key when it first enrolls.
The ID stays the same as long as the agent keeps its *writeback file*
(where it stores its key), even if the hostname or IP address changes. The
console shows hostname, operating system, last seen time and IP address,
and lets you attach **labels** (such as `servers` or `finance`) and
**metadata** (free key/value pairs such as owner or location).

The server itself can also run queries. In the console this is called the
**server**; its collections are *server collections*.

## VQL

The Velociraptor Query Language. A VQL query looks like SQL:

```sql
SELECT Name, Pid, CommandLine FROM pslist() WHERE Name =~ 'powershell'
```

Rows come from **plugins** (`pslist()`, `glob()`, `parse_evtx()`, ...)
and values are computed with **functions** (`hash()`, `upload()`,
`timestamp()`, ...). See [VQL](/vql/) and the
[VQL reference](/reference/vql/).

## Artifact

A named, reusable VQL query with a description and parameters, written in
YAML. For example `Windows.System.Pslist` lists processes and
`Windows.EventLogs.EvtxHunter` searches event logs. Atlantiraptor ships
hundreds of [built-in artifacts](/reference/artifacts/), and you can write
your own. Artifacts have a **type**:

| Type | Runs | Used for |
|---|---|---|
| `CLIENT` | once on an endpoint | collections and hunts |
| `CLIENT_EVENT` | continuously on endpoints | monitoring and detections |
| `SERVER` | once on the server | server tasks, cloud hunts, reports |
| `SERVER_EVENT` | continuously on the server | alert forwarding, automation, cloud monitoring |
| `NOTEBOOK` | in a notebook | templates for analysis |

## Collection (flow)

Running one or more artifacts on one client (or on the server) once. Each
collection gets a **flow ID** such as `F.CT2Q8M1J5G1OE`. Its results are
tables of rows, one per artifact *source*, plus logs and any uploaded files.
Collections appear on the client's **Collections** page.

## Hunt

Running the same collection on many clients: all of them, those with a
label, those of an operating system, or several organizations at once. A
hunt has a **hunt ID** such as `H.CT2QA0L3P7JBE`. Clients that are online
answer within seconds; clients that come online later join while the hunt
is running. In Atlantiraptor a hunt stops after **one hour** unless you turn
on **Run until stopped**. See [Hunts](/hunts/).

[Rapid hunt](/console/rapid-hunt/) and [IOC sweep](/console/ioc-sweep/)
are guided hunts for indicators. [Response actions](/console/response/)
are hunts that change endpoints.

## Monitoring (event artifacts)

Client event artifacts run all the time on the endpoints and send rows as
events happen: new processes, DNS lookups, Sigma rule matches. Server event
artifacts do the same on the server. Their output is stored per day and
viewed under **Client events** or **Server events**. See
[Client monitoring](/clients/monitoring/).

## Alert

A row an artifact raises with the VQL `alert()` function, for example when a
Sigma or YARA rule matches. Alerts appear on the dashboard queue, where
analysts acknowledge, close or mark them as false positives, and are sent to
your [integrations](/server-automation/integrations/). See
[Alerts](/console/alerts/).

## Notebook

A page of Markdown notes and VQL cells for analysing results. Every hunt
and collection has its own notebook; global notebooks are for
investigations. [Cases](/console/cases/) are built on notebooks. See
[Notebooks](/notebooks/).

## Organization (org)

An isolated tenant on one server, with its own clients, artifacts, hunts,
users' roles and data. Managed service providers use one organization per
customer. The first organization is the **root org**. See
[Organizations](/deployment/orgs/).

## Users, roles and permissions

People sign in to the console with a password (and two-factor code) or
through single sign-on. Each user has **roles** in each organization, such
as `reader`, `analyst`, `hunter`, `responder` or `administrator`. Roles
grant **permissions** such as `COLLECT_CLIENT` or `EXECVE`, which the server
checks for every action and query. See [Users and roles](/users/).

## Datastore and filestore

Where the server keeps its data: client records, collection results, hunt
results, uploaded files, notebooks. By default this is a directory on the
server's disk. See [Storage and data retention](/deployment/storage/).

## Accessor

How VQL reads a path. The `file` accessor uses the operating system, `ntfs`
parses the raw NTFS file system (and can read locked and deleted files),
`registry` reads the Windows registry, `zip` reads inside archives, and
there are many more. See [Paths and accessors](/forensics/).

## Tool

An external program an artifact needs, such as Autoruns or a YARA rule
pack. The server keeps a tool inventory, downloads tools once, and serves
them to agents. See [Managing external tools](/artifacts/tools/).

## Offline collector

A stand-alone program built from the Atlantiraptor binary that runs a set
of artifacts on a machine without an agent and writes the results to a zip
file or uploads them. See [Offline collections](/offline/).
