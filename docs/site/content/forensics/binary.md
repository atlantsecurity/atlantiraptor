---
title: Parsing binary formats
description: Read SQLite, ESE, plist, LevelDB, PE and custom binary structures on endpoints with Atlantiraptor VQL.
---

Most evidence lives in structured files. The agent parses many formats
itself, so artifacts can read them on the endpoint and send only the
answer.

## Built-in parsers

| Format | VQL | Used for |
|---|---|---|
| SQLite | `sqlite(file=…, query=…)` | Browser history, chat apps, many macOS and Linux databases |
| ESE (Extensible Storage Engine) | `parse_ese()`, `parse_ese_catalog()` | SRUM, Windows Search, `WebCache` |
| Property lists | `plist()` | macOS configuration and application data |
| LevelDB | `leveldb()` | Chromium-based apps' local storage |
| Windows event logs | `parse_evtx()` | Event logs |
| Registry hives | the `raw_reg` accessor | Offline hives |
| PE files | `parse_pe()` | Executables: headers, imports, exports, version info, signatures |
| Compound files (OLE) | the `mscfb` accessor | Office documents, Jump Lists |
| Outlook PST | `parse_pst()` and the `pst` accessor | Mailboxes |
| macOS unified logs | `parse_unified_logs()` | macOS logs |
| systemd journal | `parse_journald()` | Linux logs |
| Text | `parse_csv()`, `parse_jsonl()`, `parse_xml()`, `parse_yaml()`, `parse_lines()`, `parse_records_with_regex()` | Logs and configuration files |

Parsers take a file name and an accessor, so they work on files inside
zips, images or shadow copies, and on strings with the `data` accessor.

```sql
-- Chrome history straight from the database (copied first, as Chrome
-- keeps it locked)
SELECT url, title, timestamp(winfiletime=last_visit_time * 10) AS LastVisit
FROM sqlite(file="C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
            query="SELECT url, title, last_visit_time FROM urls")
```

## Custom binary structures

For formats with no parser, `parse_binary()` takes a **profile** that
describes a structure field by field, and VQL reads it from any
file or string:

```sql
LET Profile = '''[
  ["Header", 8, [
    ["Magic",   0, "String", {"length": 4}],
    ["Version", 4, "uint16"],
    ["Count",   6, "uint16"]
  ]]
]'''

SELECT parse_binary(accessor="data", filename=unhex(string="4d5a5a5a01000300"),
                    profile=Profile, struct="Header") AS Header
FROM scope()
```

returns `{"Magic": "MZZZ", "Version": 1, "Count": 3}`.

A profile is a list of structs. Each struct has a name, a size, and fields
of `[name, offset, type, options]`:

| Type | Meaning |
|---|---|
| `uint8`, `uint16`, `uint32`, `uint64`, `int8`…`int64` | Little-endian integers (`uint16be`, `uint32be`, `uint64be` for big-endian) |
| `String` | A string; options `length`, `term` (terminator), `encoding` (`utf16`) |
| `Array` | Several items; options `type`, `count` |
| `Pointer` | Follows an offset to another struct |
| `Enumeration`, `Flags`, `BitField` | Named values, flags and bit ranges |
| `Union` | One of several structs, chosen by an expression |
| `Value` | A computed value (an expression over other fields) |
| `WinFileTime`, `Timestamp` | Times |
| Another struct's name | A nested struct |

Offsets and counts can be expressions (lambdas) over other fields, so
variable-length structures work too. Built-in artifacts such as
`Windows.Registry.UserAssist` and `Windows.Registry.RecentDocs` use
profiles; read them for real examples.

## Carving

When the structure is gone, carve: `carve_evtx()` and `carve_usn()` find
records in unallocated space, memory or other files. `yara()` with a rule
for a header finds offsets to start parsing from.
