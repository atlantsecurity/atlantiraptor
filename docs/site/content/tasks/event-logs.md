---
title: Search the Windows event logs
description: Find events by ID, log, user name or IP address in the Windows event logs of one computer or all of them.
---

## Search for an event or a word

1. On the computer's [host page](/tasks/look-at-a-computer/), click
   **Collect**. (For all computers, start a **New hunt** under **Hunts**
   instead.)
2. Search for `EvtxHunter` and select `Windows.EventLogs.EvtxHunter`.
3. Open its settings and fill in what you are looking for. Leave the rest
   as it is.

   - **IocRegex**: a word that must appear in the event, such as a user
     name, IP address, program or computer name. To look for several,
     separate them with a vertical bar: `alice|203.0.113.7`.
   - **IdRegex**: the event IDs, for example `^(4624|4625)$` for sign-ins
     and failed sign-ins.
   - **ChannelRegex**: the log, for example `Security`, `System` or
     `PowerShell`.
   - **DateAfter** and **DateBefore**: a time range, for example
     `2026-11-01T00:00:00Z`.

4. Click **Collect now** (or **Create and start hunt**).

Each matching event is one row, with its time, log, ID, the computer and
the full event details. Old logs from shadow copies are searched too if
you set **VSSAnalysisAge** to a number of days.

## Useful event IDs

| ID | Log | Means |
|---|---|---|
| 4624, 4625 | Security | Successful and failed sign-in |
| 4720 | Security | A user account was created |
| 4732 | Security | A user was added to a group (such as Administrators) |
| 1102 | Security | The security log was cleared |
| 7045 | System | A service was installed |
| 4104 | PowerShell | A PowerShell script block ran |

## Just read the logs

The **Event logs** tile on the host page collects the logs in full, for
browsing. Searching with the steps above is usually faster.
