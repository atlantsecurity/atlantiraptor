---
title: Searching and collecting files
description: Find files on endpoints with glob patterns, read their metadata, hashes and signatures, and collect them to the Atlantiraptor server.
---

## Finding files with glob()

`glob()` walks the file system and returns one row per matching file:

```sql
SELECT OSPath, Size, Mtime, Btime, IsDir
FROM glob(globs="C:/Users/*/Downloads/*.{exe,dll,ps1}")
```

| Pattern | Matches |
|---|---|
| `*` | Any characters within one folder name |
| `?` | One character |
| `**` | Any number of folders, recursively |
| `**3` | Up to three folders deep |
| `{a,b}` | Either alternative |
| `[abc]` | One of the characters |

Matching is case-insensitive on Windows. Pass several patterns as a list,
and `glob()` walks the disk only once for all of them:

```sql
SELECT OSPath FROM glob(globs=["C:/Windows/Temp/**", "C:/ProgramData/*.exe"])
```

Each row has `OSPath`, `Name`, `Size`, `IsDir`, `IsLink`, the four
timestamps (`Mtime`, `Atime`, `Ctime`, `Btime`), `Mode`, and in `Data`
accessor-specific details (for NTFS, the MFT entry and more).

`root=` starts the search somewhere other than the file system root, which
is how you search inside zips, images or another accessor's view.

## About a file

| Function | Returns |
|---|---|
| `stat(filename=…)` | The same metadata as a `glob()` row, for one file |
| `hash(path=…)` | MD5, SHA1 and SHA256 |
| `authenticode(filename=…)` | Windows signature: signer, issuer, whether it is trusted |
| `parse_pe(file=…)` | PE headers, imports, exports, version information |
| `magic(path=…)` | The file type, from its content |
| `read_file(filename=…, length=…)` | The content, or the first bytes of it |

## Searching by content

- `yara()` matches rules against files: see [YARA](/vql/yara/).
- `parse_lines()` and `parse_records_with_regex()` read text files line by
  line or record by record; combine them with `=~` to grep.
- `Windows.Search.FileFinder` searches by name, time, size and YARA, with
  optional upload and hashing, and is the usual artifact to hunt files.

## Collecting files {#collecting-files}

`upload()` sends a file to the server, where it is stored with its hashes
and appears in the collection's **Files** tab:

```sql
SELECT OSPath, upload(file=OSPath) AS Upload
FROM glob(globs="C:/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk")
```

Ready-made artifacts:

| Artifact | Collects |
|---|---|
| `Generic.Collectors.File` | Every file matching a table of globs, through any accessor (locked files with `ntfs`) |
| `Windows.Search.FileFinder` | Files matching a search, if `Upload_File` is set |
| `Windows.NTFS.MFT` | The parsed MFT, filtered by path, name, size and time |

Uploads count against the collection's `max_upload_bytes`. Large files are
sent in chunks and resume if the connection drops.

## Timestamps

| Column | Meaning |
|---|---|
| `Mtime` | Content last modified |
| `Atime` | Last accessed (often disabled or delayed by the OS) |
| `Ctime` | Metadata last changed on Unix; on Windows through the `file` accessor, the change time |
| `Btime` | Created ("born") |

On NTFS, the `ntfs` accessor gives both the `$STANDARD_INFORMATION`
timestamps (easily changed by tools) and the `$FILE_NAME` ones (much
harder to change). A mismatch suggests timestomping; see
[NTFS](/forensics/ntfs/).
