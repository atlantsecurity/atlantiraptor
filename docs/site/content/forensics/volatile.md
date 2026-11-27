---
title: Volatile evidence
description: Collect processes, process memory, network connections, handles and full memory images with Atlantiraptor before they disappear.
---

Volatile evidence exists only while the machine runs: processes, network
connections, memory. Collect it first, before rebooting, isolating with
tools that restart the machine, or pulling the power.

## Processes

| Artifact | Gives |
|---|---|
| `Windows.System.Pslist` | Processes with command lines, users, hashes and signatures (filters for name, path, user, unsigned only) |
| `Linux.Sys.Pslist` | Processes on Linux |
| `Generic.System.Pstree` | The process tree, with each process's chain of parents |
| `Windows.Memory.ProcessInfo` | Process details from memory: environment, loaded modules |
| `Windows.System.DLLs` | DLLs loaded in each process |
| `Windows.System.Handles` | Open handles (files, registry keys, mutexes) |
| `Windows.System.VAD` | Memory regions; finds injected code (executable private memory) |
| `Windows.System.Threads` | Threads |
| `Linux.Sys.Maps` | Memory maps of Linux processes |

In VQL: `pslist()`, `modules(pid=)`, `handles(pid=)`, `vad(pid=)`,
`threads(pid=)` and `token(pid=)` (the process's user, groups and
privileges).

### Process tracking

Processes that already exited don't appear in `pslist()`. The **process
tracker** remembers them: enable `Windows.Events.TrackProcesses` (Sysmon
based) or `Windows.Events.TrackProcessesBasic` as a monitoring artifact,
and `process_tracker_pslist()` and `process_tracker_tree()` then include
exited processes and full parent chains. Artifacts such as
`Windows.System.Pslist` use it when their `UseTracker` option is on.

## Process memory

- `Windows.Memory.ProcessDump` writes a full dump of matching processes
  (also openable in WinDbg) and uploads it.
- `proc_dump(pid=)` does the same in VQL.
- `Windows.Detection.Yara.Process` and `proc_yara()` scan process memory
  with YARA without dumping it.
- The `process` accessor reads a process's memory like a file, for
  `yara()` or `parse_binary()`.

## Full memory image

`Windows.Memory.Acquisition` acquires physical memory with the built-in
WinPmem driver and uploads the image, optionally compressed. A memory image
is as big as the machine's RAM: raise the collection's timeout and upload
limit first, and make sure the server has room.

`Windows.Detection.Yara.PhysicalMemory` scans physical memory with YARA
without uploading it, and the `winpmem` accessor reads it from VQL.

Analyse the image with your memory forensics tools (Volatility, MemProcFS).

## Network

| Artifact | Gives |
|---|---|
| `Windows.Network.Netstat`, `Linux.Network.Netstat` | Connections and listening sockets, with the owning process |
| `Windows.Network.NetstatEnriched`, `Linux.Network.NetstatEnriched` | The same with process details, hashes and signatures |
| `Windows.Network.ListeningPorts` | Listening ports only |
| `Windows.System.DNSCache` | The DNS resolver cache: names the machine looked up recently |
| `Windows.Network.ArpCache`, `Linux.Proc.Arp` | Neighbours on the local network |
| `Windows.Network.PacketCapture`, `Linux.Network.PacketCapture` | A packet capture for a set time |

`netstat()` gives the raw table in VQL.

## Order of collection

A reasonable order, most volatile first:

1. Processes with hashes and the process tree, network connections, DNS
   cache.
2. Process dumps of anything suspicious, or a full memory image.
3. Then disk evidence (event logs, execution evidence, file system).

The host page's **Full triage** collects the first group and persistence
in one go.
