---
title: Forensics
description: How Atlantiraptor reads evidence on endpoints - accessors, paths, file systems, NTFS, Windows artifacts, disk images, binary formats and volatile data.
---

Atlantiraptor's agent is a forensic toolkit as well as a collector: it
parses NTFS, the registry, event logs, SQLite databases, prefetch files
and many other formats itself, on the endpoint, without external tools.
This section explains how that works so you can choose the right
artifact, or write your own.

| Page | Covers |
|---|---|
| [Searching and collecting files](/forensics/filesystem/) | `glob()`, file metadata, hashes, timestamps, collecting files |
| [NTFS](/forensics/ntfs/) | The raw NTFS parser: locked files, the MFT, the USN journal, alternate data streams, shadow copies |
| [Windows evidence](/forensics/windows/) | Event logs, the registry, execution evidence, browser history, persistence |
| [Disk images and dead disks](/forensics/deaddisk/) | Analysing an image or a mounted disk with the same artifacts |
| [Parsing binary formats](/forensics/binary/) | SQLite, ESE, plists, PE files and custom binary structures |
| [Volatile evidence](/forensics/volatile/) | Processes, memory, network connections, handles |

## Accessors

Every function that reads a file takes an `accessor`: the method used to
read it. The same path means different things through different accessors.

| Accessor | Reads |
|---|---|
| `file` | Files through the operating system (the default) |
| `auto` | Like `file`, but falls back to `ntfs` for locked files on Windows |
| `ntfs` | NTFS by parsing the disk directly: locked files, deleted entries, alternate data streams |
| `ntfs_vss` | NTFS including every Volume Shadow Copy |
| `mft` | Individual MFT entries and their streams |
| `registry` (`reg`) | The live Windows registry, through the API |
| `raw_reg` | A registry hive file, parsed directly |
| `data` | A string, as if it were a file |
| `zip`, `gzip`, `bzip2` | Inside compressed files |
| `collector` | Inside an offline collection zip |
| `process` | A process's memory |
| `raw_ntfs`, `raw_ext4`, `fat` | File systems inside disk images |
| `ewf`, `vmdk`, `vhdx` | Disk image formats |
| `offset`, `sparse`, `ranged` | Parts of another file |
| `smb`, `ssh`, `s3` | Remote storage |
| `vfs`, `fs` | (Server) the client's VFS copy, the server's file store |

```sql
-- Read a locked registry hive
SELECT * FROM glob(globs="C:/Windows/System32/config/SAM", accessor="ntfs")

-- Read a file inside a zip
SELECT * FROM glob(globs="/**", root="C:/evidence/bundle.zip", accessor="zip")
```

The full list, with each accessor's details, is in the
[VQL reference](/reference/vql/).

## Paths and OSPath

Paths in VQL are objects (`OSPath`), not plain strings. They know their
components, their accessor and their operating system's rules:

```sql
SELECT OSPath, OSPath.Basename, OSPath.Dirname, OSPath.Components
FROM glob(globs="C:/Windows/*.exe")
```

- Forward slashes work everywhere, also on Windows.
- `OSPath.Basename`, `.Dirname`, `.Components`, and `+` to add a
  component (`OSPath + "sub"`).
- `pathspec()` builds paths that nest accessors, for example a file inside
  an NTFS image inside a zip.

## Timestamps

Forensic artifacts return times in UTC. The console shows them in your
time zone. NTFS keeps several sets of timestamps per file (see
[NTFS](/forensics/ntfs/)); built-in artifacts name them consistently:
`Mtime` (modified), `Atime` (accessed), `Ctime` (metadata changed) and
`Btime` (born, or created).
