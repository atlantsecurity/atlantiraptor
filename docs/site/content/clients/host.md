---
title: The host page
description: Triage one endpoint from its Atlantiraptor host page - overview, quick triage, full triage with findings and an activity timeline, quarantine and metadata.
---

Open a host from search, the client list, an alert or any client ID link.
The **Overview** shows who the machine is and what is happening on it, and
lets you collect evidence in one click without leaving the page.

## Overview

The top of the page shows the host name, operating system, agent version,
when it was last seen and from which IP address, labels, and whether it is
quarantined. The menu has **Interrogate** (refresh host information),
**Quarantine host…** and other actions.

## Quick triage

Each tile collects one thing from the host. You stay on the page; a
notification tells you when the collection finishes, and the result is
under **Recent collections**.

![Host page with quick triage tiles](/images/host-triage.webp "A Linux host's page: full triage findings, quick triage tiles, system and connectivity.")

| Windows | Linux | macOS |
|---|---|---|
| Processes (with hashes and signers) | Processes | Processes (tree) |
| Network connections | Network connections | Network connections |
| Users | Users (`/etc/passwd`) | Users |
| Services | Logins (wtmp) | Launch agents |
| Autoruns | Cron jobs | Shell history |
| Scheduled tasks | SSH keys | |
| Event logs | Shell history | |
| Browser history (Chrome, Edge, Brave, Firefox) | Triage package (UAC) | |
| Downloads history (with Zone.Identifier) | | |
| Recently run programs (Prefetch, Amcache, ShimCache, BAM, UserAssist) | | |
| MFT (time window) | | |
| Triage package (KAPE-style file set) | | |

**MFT (time window)** asks for a drive and a start and end time (in your
local time zone) and collects only the NTFS entries created, modified or
changed in that window, which is far quicker than the whole MFT.

The tiles use the standard artifacts (for example `Windows.System.Pslist`,
`Windows.Network.Netstat`, `Windows.KapeFiles.Targets`), so you can also run
them with custom parameters from **Collections**.

> **Note** The **Triage package** tiles run `Windows.KapeFiles.Targets`
> (Windows) and `Linux.Collection.UAC` (Linux), which are not built in.
> Import them first (see
> [Importing more artifacts](/artifacts/managing/#importing-more-artifacts)).

## Full triage

**Full triage** collects processes, network connections, persistence
(autoruns, services, scheduled tasks), users and execution history in one
collection. As results arrive, the page shows:

### Worth a look

Findings that deserve attention, each with why it matters:

- programs running from AppData, Temp, ProgramData or `/tmp`,
- processes whose file was deleted from disk,
- unsigned programs (common for in-house tools; review the ones you don't
  recognise),
- persistence (autoruns, services, tasks) pointing into user-writable
  folders,
- processes with connections to the internet,
- execution evidence from Prefetch for programs that are gone.

Findings are hints, not verdicts. Pivot on any value to see if other
machines have it too.

### Activity timeline

A single timeline of what happened on the host: process starts, program
executions, logons, network activity and persistence changes, from the
triage results. Scroll back from the most recent events, filter, and click
an event for details.

![Activity timeline on the host page](/images/host-timeline.webp "The activity timeline built from the full triage results.")

## Quarantine

**Quarantine host…** cuts the machine off the network, except for its
connection to the Atlantiraptor server, so you can keep investigating
while the threat cannot spread or exfiltrate. You can show a message to
the user ("This computer has been isolated by the security team"). The host
gets the `Quarantine` label and the page shows it as isolated.
**Lift quarantine** restores normal network access.

Quarantine needs the `responder` role. For many hosts at once, use
[Response actions](/console/response/).

## Metadata

The **Metadata** card holds key/value pairs for this host: owner, location,
asset tag, case number. See [Metadata](/clients/#metadata).

## Other pages for the host

When a host is selected, the **Client** section of the sidebar has:

- [Files](/clients/files/): browse its file system and registry,
- [Collections](/clients/collections/): everything collected from it,
- [Client events](/clients/monitoring/): its monitoring data,
- [Shell](/clients/shell/): run commands (from the host's menu or the
  Collections page).
