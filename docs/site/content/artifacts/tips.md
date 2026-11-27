---
title: Tips for artifact writers
description: Patterns that make Atlantiraptor artifacts fast, light on endpoints and easy to use.
---

## Filter early, on the client

Filter on cheap columns before calling expensive functions, and send only
the rows you need to the server:

```sql
-- Slow: hashes every file, even directories and huge files
SELECT OSPath, hash(path=OSPath).SHA256 AS SHA256 FROM glob(globs=Glob)

-- Fast: filters on what glob() already knows, hashes the rest
LET files = SELECT OSPath FROM glob(globs=Glob)
  WHERE NOT IsDir AND Size < 10000000

SELECT OSPath, hash(path=OSPath).SHA256 AS SHA256 FROM files
```

## Use LET for stored and lazy queries

`LET x = SELECT …` is lazy: the query runs each time `x` is used. `LET x <=
SELECT …` runs once and keeps the rows. Use `<=` for small lookup tables
used many times, and `=` for large results that are only read once.

## Narrow globs

`C:/Users/*/AppData/Roaming/**/*.exe` is far cheaper than `C:/**/*.exe`.
Recursive `**` walks every folder below it; put it as deep in the path as
you can, and use `**3` to limit the depth when that's enough.

## Use the right accessor

Use `ntfs` (or `auto`) only for locked files and NTFS metadata; it is
slower than the `file` accessor. Use `registry` for live registry keys and
`raw_reg` to parse hive files. See [Forensics](/forensics/).

## Upload with care

`upload()` sends a file to the server. Collect paths and metadata first,
let the user choose with a parameter (`Upload_File: N` by default), and set
`max_upload_bytes`.

## Make columns useful

- Name every column with `AS`, in the same terms as built-in artifacts.
- Return timestamps as times, not strings, so they sort and the console
  shows them in the user's time zone.
- Hide raw blobs that people rarely need behind a leading underscore
  (`EventData AS _EventData`): the console hides those columns by default.

## Don't block forever

Client queries stop at the timeout (600 seconds by default). For artifacts
that call external programs, pass a timeout to `execve()` where it applies,
and set `resources.timeout` for long jobs.

## Test on one machine, then a few, then everyone

The collection log shows how long each query took and how many rows it
returned. Watch `Generic.Client.Stats` when trying event artifacts.

## Reuse

Call existing artifacts (`SELECT * FROM Artifact.Windows.System.Pslist()`)
instead of copying their queries, and share helper `LET` definitions with
`export` and `imports`.
