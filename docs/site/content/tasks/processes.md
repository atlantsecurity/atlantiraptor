---
title: See what's running and who it talks to
description: List the running programs on a computer with their hashes and signers, and its network connections with the program behind each one.
---

## On one computer

1. Open the computer's [host page](/tasks/look-at-a-computer/).
2. Click the **Processes** tile. On Windows you get every running program
   with its command line, user, start time, file hash and whether the file
   is signed, and by whom.
3. Click the **Network connections** tile. You get every open connection
   and listening port, with the program that owns it.

Open the result under **Recent collections**. In the table:

- type in the filter box above a column to narrow it down, for example
  `powershell` in the name column,
- click a column title to sort by it,
- click any value, such as a hash or a remote IP address, to hunt for it
  on all computers or copy it.

![Hunting from a value in a result](/images/pivot-menu.webp "Click a value in any result to hunt for it on every computer.")

**Full triage** on the host page does both at once and flags the programs
that are worth a look.

## On every computer

To list the programs running everywhere, for example to find every
computer that runs a remote access tool:

1. Open **Hunts** and click **New hunt**.
2. Search for `Pslist` and select `Windows.System.Pslist` (and
   `Linux.Sys.Pslist` for Linux computers).
3. Keep **All clients** and click **Create and start hunt**.

The hunt's **Results** tab shows the programs from all computers in one
table, with the computer's name on each row. See
[Ask every computer the same question](/tasks/every-computer/).

If you only want to know whether one program runs anywhere, a
[Rapid hunt](/first-hunt/) for its name is quicker.

## What to do next

- A program you don't trust: [kill it](/tasks/stop-a-threat/), or
  [capture its memory](/tasks/memory/) first.
- A computer talking to a bad address: [quarantine it](/tasks/quarantine/).
