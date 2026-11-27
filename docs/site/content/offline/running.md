---
title: Running a collector
description: Run an Atlantiraptor offline collector on an endpoint, by hand or remotely, and get its results back.
---

## On Windows

Copy the collector to the machine (a USB stick, a share, a remote admin
tool) and run it **as administrator**: right-click, **Run as
administrator**, or start it from an elevated command prompt. Without
administrator rights it stops with an error, because most forensic
artifacts need them.

A console window shows progress. When it finishes, the results are in
the folder it was started from (or the configured output folder):

```text
Collection-WS-0142-2026-11-27T10_14_05Z.zip
Collection-WS-0142-2026-11-27T10_14_05Z.log
```

The `.log` file is the collector's log; keep it with the zip.

## On Linux and macOS

```bash
chmod +x Collector_atlantiraptor-linux-amd64
sudo ./Collector_atlantiraptor-linux-amd64
```

On macOS, a downloaded collector is quarantined by Gatekeeper. Remove the
attribute first: `xattr -d com.apple.quarantine ./Collector_…`. For full
disk access to protected folders, run it from a terminal that has Full
Disk Access.

## Running remotely

The collector needs no arguments and no network (unless it uploads), so it
works with any way of running a program on a remote machine:

- PsExec, WinRM or PowerShell remoting: copy it, then run it as SYSTEM
  or an administrator,
- your EDR's or RMM's "run script" feature,
- a scheduled task or a GPO startup script for many machines.

Turn **Pause For Prompt** off for unattended runs, so it exits when done.

## How long it takes, and the load

A small set of artifacts finishes in a minute or two. File collections
(event logs, `$MFT`, registry hives) take longer and produce bigger zips.
The collector runs at normal priority; set a **CPU Limit Percent** when
building it if the machine must stay responsive.

## Sending results somewhere

If the collector was built with an upload target (S3, Google Cloud
Storage, Azure, SMB or SFTP), it uploads the zip when it finishes and
writes the result of the upload in its log. With **Delete Collection at
Exit**, the local copy is then removed.

Otherwise, bring the zip back the way you took the collector there. If it
was built with X509 encryption, it can travel over untrusted channels
(email, a shared drive) because only your server can decrypt it.

## If something goes wrong

- **It closes at once**: run it from a command prompt to see the error, or
  read the `.log` file.
- **Access denied**: it was not run as administrator (or root).
- **Antivirus removes it**: collectors are signed agents with an embedded
  configuration, but some products still block forensic tools. Add an
  exclusion for the run, or use a collector your security product already
  trusts.
- **An artifact returned nothing**: check the log for that artifact's
  errors, then try the same artifact as a collection on a machine with an
  agent.
