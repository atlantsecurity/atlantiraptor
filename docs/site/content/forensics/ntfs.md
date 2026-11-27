---
title: NTFS
description: Atlantiraptor's raw NTFS parser - locked files, the MFT, deleted files, timestomping, the USN journal, alternate data streams and Volume Shadow Copies.
---

On Windows, the agent can read NTFS volumes by parsing the disk itself
instead of asking the operating system. This bypasses file locks and
permissions, and shows things the operating system hides.

## The ntfs accessor

Use `accessor="ntfs"` (or `auto`, which tries the normal API first) to:

- read locked files: registry hives, `pagefile.sys`, in-use databases and
  event logs,
- read NTFS metafiles: `C:/$MFT`, `C:/$Extend/$UsnJrnl:$J`, `C:/$LogFile`,
- read alternate data streams, written as `file:stream` (for example
  `Zone.Identifier`),
- see entries for deleted files that are still in the MFT.

```sql
SELECT OSPath, Size FROM glob(globs="C:/Windows/System32/config/*",
                              accessor="ntfs")
```

Paths through the `ntfs` accessor can also name the device, such as
`\\.\C:\Windows`.

## The MFT

The Master File Table has one entry for every file and folder, including
recently deleted ones. Parsing it gives a complete listing of the volume
in a few minutes, with timestamps the operating system doesn't show.

`Windows.NTFS.MFT` parses it with filters for path, file name, size and
time window (the host page's **MFT (time window)** tile uses it). Each
row includes:

- both sets of timestamps: `$STANDARD_INFORMATION` (what Explorer shows,
  easy to change) and `$FILE_NAME` (changed only by the file system),
- `SI_Lt_FN`: the `$STANDARD_INFORMATION` creation time is earlier than
  the `$FILE_NAME` one, a classic sign of timestomping,
- `USecZeros`: timestamps with zero sub-second parts, typical of tools
  that set times,
- `InUse`: false for deleted entries,
- `HasADS`: the file has alternate data streams.

`parse_mft()` does the same from VQL, also on an MFT file collected
earlier.

## Recovering deleted files

As long as a deleted file's MFT entry and clusters haven't been reused,
`Windows.NTFS.Recover` can recover it: find its MFT entry number with
`Windows.NTFS.MFT`, then collect `Windows.NTFS.Recover` with that number.

## The USN journal

The USN journal (`$UsnJrnl:$J`) records changes to files: creation,
renames, writes, deletion. It often covers days or weeks and survives the
deletion of the files it mentions.

- `Windows.Forensics.Usn` parses it, filtered by file name, path and time.
- `Windows.Detection.Usn` watches it live as a monitoring artifact.
- `carve_usn()` finds USN records in unallocated space or memory images.

## Alternate data streams and extended attributes

- `Windows.NTFS.ADSHunter` finds files with unusual alternate data streams
  (malware hides payloads there).
- The `Zone.Identifier` stream records where a downloaded file came from;
  the host page's **Downloads history** tile reads it.
- `Windows.NTFS.ExtendedAttributes` lists NTFS extended attributes.

## $I30 index slack

Folder indexes (`$I30`) keep traces of files that were deleted from the
folder. `Windows.NTFS.I30` parses them.

## Volume Shadow Copies

The `ntfs_vss` accessor reads a path in the live volume and in every
shadow copy, so you can find older versions of a file or files deleted
since the snapshot:

```sql
SELECT OSPath, Size, Mtime
FROM glob(globs="C:/Users/*/NTUSER.DAT", accessor="ntfs_vss")
```

## Performance

Parsing NTFS is heavier than using the API. The agent caches parsed
volume data for a short time (`NTFS_CACHE_TIME` in some artifacts), so
several queries in one collection share the work. Prefer `auto` over
`ntfs` when most files are not locked.
