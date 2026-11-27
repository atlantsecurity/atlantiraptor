---
title: IOC sweep
description: Hunt the fleet for a list of hashes, IP addresses, domains, paths and file names in one hunt, with hits raised as alerts.
---

An IOC sweep checks every endpoint for a whole list of indicators of
compromise at once, for example from a threat report or a MISP event. Hits
appear per client and, optionally, as dashboard [alerts](/console/alerts/).

Open **IOC sweep** in the sidebar, or paste several indicators into the
[command palette](/console/#the-command-palette) or Rapid hunt.

## Indicators

Paste indicators one per line, in any mix, or as `type,value,note` lines.
Defanged values (`hxxps://`, `evil[.]example`) are fine, and URLs are
reduced to their host name. The page recognises:

| Type | Each endpoint checks |
|---|---|
| `sha256`, `sha1`, `md5` | Hashes of files in the search folders (below) |
| `ip` | Remote addresses of current network connections |
| `domain` | The Windows DNS client cache (subdomains match too) |
| `path` | Whether a file or folder exists at the path (globs allowed) |
| `filename` | File names in the search folders (case-insensitive) |

Review the parsed list before you start: the page shows how each line was
understood.

## Options

- **Where to look for hashes and file names**: a glob of folders to scan.
  The default covers users' Downloads, Desktop, Documents, temp and
  roaming application data. Wider globs find more and take longer. Files
  larger than 100 MB are not hashed.
- **Raise a dashboard alert for each hit**: on by default, with severity
  *high*.
- **Target**: all clients, clients with labels, or clients of one
  operating system.
- **Run until stopped**: off by default (the sweep stops after one hour).

Click **Sweep for N indicators**. The sweep is a hunt of `Generic.Detection.IOCSweep`, so it
also appears under [Hunts](/hunts/).

## Results

Open a sweep to see hits per client: which indicator matched, where, and
the details (file path and hash, connection and process, DNS entry). From
there, pivot, respond or add hits to a case as anywhere else.

## Importing from MISP

If your administrator connected MISP under
[Integrations](/server-automation/integrations/#misp), **Import into IOC
sweep** pulls recent indicators (optionally only those flagged for
detection, published in the last N days) into a sweep you review before
running.

## From the API

`POST /api/atl/v1/ioc-sweeps` starts a sweep with a list of indicators. See
the [REST API reference](/reference/api/).
