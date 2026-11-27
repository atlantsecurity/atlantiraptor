---
title: Capture memory
description: Dump the memory of one suspicious program, or take a full memory image of a Windows computer, for analysis in other tools.
---

Memory shows what a program is really doing: decrypted strings, injected
code, network addresses, commands. There are two ways to capture it.

## One program's memory

Quick and small, usually enough for a suspicious program.

1. Find the program's name or process ID (PID), for example with the
   **Processes** tile (see [See what's running](/tasks/processes/)).
2. On the computer's [host page](/tasks/look-at-a-computer/), click
   **Collect**.
3. Search for `ProcessDump` and select `Windows.Memory.ProcessDump`.
4. Open its settings and set **ProcessRegex** to the program's name, for
   example `evil\.exe` (a dot needs a `\` in front), or set **PidRegex**
   to its PID, for example `^4312$`.
5. Click **Collect now**.

The dump appears on the collection's **Files** tab, one per matching
process. Download it and open it in your usual analysis tool.

On Linux, use `Linux.Triage.ProcessMemory` and set **processPid** to the
PID.

## The whole computer's memory (Windows)

A full memory image, for in-depth analysis with tools like Volatility. It
is as big as the computer's memory, so it takes a while and needs room on
the server.

1. On the host page, click **Collect**.
2. Search for `Memory.Acquisition` and select `Windows.Memory.Acquisition`.
3. Optionally set **Compression** to `S2`: the image becomes smaller and
   uploads faster, and you decompress it before analysis.
4. Under **Limits**, raise:
   - **Timeout (s)** to `7200` (two hours),
   - **Max upload (MB)** to more than the computer's memory, for example
     `65536` for a computer with 32 GB. The default of 1024 MB stops the
     upload of anything bigger.
5. Click **Collect now**.

When it is done, the image `PhysicalMemory.dd` is on the collection's
**Files** tab. A compressed image is decompressed with the free
[WinPmem](https://github.com/Velocidex/WinPmem/releases) tool:
`go-winpmem.exe extract image.compressed image.raw`.

Capture memory **before** you kill a program, restart or quarantine the
computer: once the program is gone, so is its memory.
