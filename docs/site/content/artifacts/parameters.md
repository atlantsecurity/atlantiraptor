---
title: Artifact parameters
description: Declare parameters in Atlantiraptor artifacts - types, defaults, choices, CSV and JSON tables, uploads - and how they reach the VQL query.
---

Parameters let users change what an artifact does without editing it: a
path to search, a time range, a list of hashes. In the query they are
plain variables with the parameter's name.

```yaml
parameters:
  - name: DateAfter
    type: timestamp
    description: Only events after this time.
  - name: Hashes
    type: csv
    default: |
      SHA256,Note
      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,empty file
```

## Fields

| Field | Meaning |
|---|---|
| `name` | The variable name in the query. Names with spaces work (written as `` `My Name` `` in VQL) but are best avoided |
| `default` | The value when the user doesn't set one. Always a string in YAML |
| `type` | How the value is shown in the console and converted for the query (below). Empty means a string |
| `description` | Shown next to the field in the console. Say what format is expected |
| `choices` | The allowed values, for `choices` and `multichoice` |
| `friendly_name` | A label to show instead of the name |
| `artifact_type` | For `artifactset`: which kind of artifacts to offer |

## Types

Values always travel to the client as strings. The type decides how the
console lets the user enter the value, and how the value is converted
before the query runs.

In the console, `bool` is a switch, `choices` a drop-down, `multichoice` a
set of buttons, numbers a number box, and `timestamp` a text field that
takes RFC 3339 times such as `2026-01-31T00:00:00Z` (UTC). Everything else
is a text box, which grows for multi-line values such as CSV, JSON or YARA
rules. `hidden` parameters are not shown.

| Type | In the query |
|---|---|
| *(empty)*, `string` | A string |
| `int`, `int64` | An integer |
| `float` | A float |
| `bool` | `TRUE` or `FALSE` (`Y`, `YES`, `TRUE` and `OK` count as true) |
| `timestamp` | A time |
| `choices` | A string, one of `choices` |
| `multichoice`, `json_array`, `regex_array` | An array, entered as a JSON list such as `["a", "b"]` |
| `regex` | A string, to use with `=~` |
| `csv` | Rows, one per line of the CSV, with the header as column names |
| `json` | The parsed object |
| `yaml`, `xml` | The parsed document |
| `yara` | A string with the rules |
| `upload`, `upload_file` | The value is a URL. The content is downloaded when the query runs: `upload` gives the content, `upload_file` a temporary file holding it |
| `artifactset` | Rows of artifact names (entered as CSV) |
| `hidden` | A string; for parameters set only by other artifacts |
| `redacted` | A string, hidden in logs |
| `server_metadata` | The server's metadata value of the same name, if set (for settings an administrator keeps in one place) |

## Using parameters

A `csv` parameter is a table you can query:

```sql
SELECT * FROM glob(globs="C:/Users/*/Downloads/**")
WHERE hash(path=OSPath).SHA256 IN Hashes.SHA256
```

A `timestamp` compares with times directly:

```sql
SELECT * FROM parse_evtx(filename=EvtxPath)
WHERE System.TimeCreated.SystemTime > DateAfter
```

A `bool` is used as a condition:

```sql
WHERE NOT OnlyUnsigned OR Signed != "trusted"
```

## Setting parameters from VQL

When an artifact is called from another, its parameters are arguments.
Values can be strings (converted as above) or already the right type:

```sql
SELECT * FROM Artifact.Windows.Search.FileFinder(
    Glob="C:/Users/*/AppData/**/*.ps1", Calculate_Hash=TRUE)
```

In `collect_client()` and `hunt()`, parameters are given per artifact in
`spec`:

```sql
SELECT collect_client(client_id="C.1a2b3c4d5e6f7a8b",
    artifacts="Windows.Search.FileFinder",
    spec=dict(`Windows.Search.FileFinder`=dict(
        Glob="C:/Users/*/Downloads/*.exe")))
FROM scope()
```

## Good defaults

Make the default useful on its own: most users never change parameters.
A search artifact should default to the places that matter most, and a
time range to something recent rather than "everything".
