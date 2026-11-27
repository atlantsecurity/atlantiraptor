---
title: Windows evidence
description: Collect and read Windows evidence with Atlantiraptor - event logs, the registry, execution evidence, user activity, browser history and persistence.
---

This page maps common Windows investigation questions to the artifacts
and VQL that answer them. Every artifact named here is built in; see the
[artifact reference](/reference/artifacts/) for their parameters.

## Event logs

| Artifact | Gives |
|---|---|
| `Windows.EventLogs.Evtx` | Every event from the logs matching a glob, in a time window |
| `Windows.EventLogs.EvtxHunter` | Events matching a regex anywhere in them (an IP, a user, a file name), across all logs and shadow copies |
| `Windows.EventLogs.RDPAuth` | RDP logons and logoffs |
| `Windows.EventLogs.ExplicitLogon`, `AlternateLogon` | `runas`-style logons with other credentials |
| `Windows.EventLogs.PowershellScriptblock`, `PowershellModule` | PowerShell script blocks and module logging |
| `Windows.EventLogs.Cleared` | Logs that were cleared |
| `Windows.EventLogs.ScheduledTasks` | Scheduled task creation and changes |
| `Windows.Sigma.EventLogs` | [Sigma rules](/vql/sigma/) over the logs |

In VQL, `parse_evtx(filename=…)` reads a log file (through any accessor, so
also from shadow copies or a collected zip), and `watch_evtx()` follows a
log live. Events have `System` (time, ID, channel, computer, user) and
`EventData` or `UserData` fields. Messages are not formatted; the event ID
and fields are what matter.

`carve_evtx()` recovers event records from unallocated space, memory or
other files, which helps after a log was cleared.

## Registry

- The `registry` accessor reads the live registry; keys are folders and
  values are files: `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\*`.
- The `raw_reg` accessor parses a hive file, such as a user's
  `NTUSER.DAT` (through `ntfs` if it is loaded), or a hive from an image.
- `read_reg_key()` returns all values of a key as one row.

`HKEY_USERS` only contains users who are logged on. To cover every user,
artifacts such as `Windows.Registry.NTUser` parse each user's hive file
directly.

## Execution evidence: what ran, and when

| Artifact | Source | Tells you |
|---|---|---|
| `Windows.Forensics.Prefetch` | Prefetch files | Programs run, run count, last eight run times, files they loaded |
| `Windows.Forensics.Amcache` | Amcache.hve | Programs present or run, with SHA1 hashes |
| `Windows.Registry.AppCompatCache` | ShimCache | Programs seen by the OS, in order |
| `Windows.Forensics.Bam` | Background Activity Moderator | Last run time per user |
| `Windows.Registry.UserAssist` | UserAssist | GUI programs a user started, with counts |
| `Windows.Forensics.SRUM` | System Resource Usage Monitor | Per-application network and resource use, for about 30 days |
| `Windows.Forensics.RecentApps` | RecentApps | Recently used applications per user |

The host page's **Recently run programs** tile collects the first five
together.

## User activity

| Artifact | Gives |
|---|---|
| `Windows.Forensics.Lnk` | Shortcut files: files and folders a user opened, with their original paths and volume |
| `Windows.Forensics.JumpLists` | Recently and frequently used files per application |
| `Windows.Forensics.Shellbags` | Folders a user browsed, including on removable and network drives |
| `Windows.Registry.RecentDocs` | Recently opened documents |
| `Windows.Forensics.RecycleBin` | Deleted files in the recycle bin, with their original paths |
| `Windows.Registry.MountPoints2` | Drives and shares a user mounted |
| `Windows.Forensics.RDPCache` | The RDP bitmap cache (what the user saw on a remote screen) |
| `Windows.Forensics.Timeline` | The Windows activity timeline |

## Browser history

| Artifact | Gives |
|---|---|
| `Windows.Applications.Chrome.History`, `Edge.History`, `Firefox.History` | Visited URLs and times |
| `Windows.Applications.Chrome.Downloads`, `Firefox.Downloads` | Downloads, with source URL |
| `Windows.Applications.Chrome.Extensions` | Installed extensions and their permissions |

Browsers keep their history in SQLite databases, which the agent reads
with `sqlite()` (copying locked files first). The host page's **Browser
history** tile covers Chrome, Edge, Brave and Firefox.

## Persistence

| Artifact | Gives |
|---|---|
| `Windows.Sys.StartupItems` | Run keys and startup folders |
| `Windows.Sysinternals.Autoruns` | Everything Autoruns finds (downloads the Sysinternals tool) |
| `Windows.System.Services` | Services, with their binaries and signers |
| `Windows.System.TaskScheduler` | Scheduled tasks and their actions |
| `Windows.Persistence.PermanentWMIEvents` | WMI event subscriptions |
| `Windows.Persistence.PowershellProfile` | PowerShell profiles |
| `Windows.Persistence.Debug`, `SilentProcessExit` | Debugger and image hijacks |

## Users and accounts

- `Windows.Sys.Users`: user profiles, with SIDs and last logon.
- `Windows.Forensics.SAM`: local accounts from the SAM hive.
- `Windows.System.LocalAdmins`: members of the local Administrators group.

## Building a timeline

Collect several of these artifacts in one collection or hunt, then merge
them in a notebook with `timeline_add()` (see
[Notebooks](/notebooks/#timelines)), or export them to a timeline tool.
The host page's **Full triage** builds an activity timeline for you.
