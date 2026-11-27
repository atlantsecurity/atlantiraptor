---
title: Writing artifacts
description: The structure of an Atlantiraptor artifact - sources, preconditions, parameters, resources, tools, exports and imports - and how to test one.
---

Write an artifact when you will run the same query more than once, on more
than one machine, or want others to run it without knowing VQL. Start
from the console (**Artifacts**, **New**, or **Customize** an existing
one) or in your own editor, and save it with **Check and save**, which
checks the YAML and the VQL before storing it.

## A complete example

```yaml
name: Custom.Windows.Persistence.RunKeys
description: |
  Run and RunOnce registry values for the machine and every user,
  with the file they point to and whether it is signed.

author: Security team <soc@example.com>
reference:
  - https://attack.mitre.org/techniques/T1547/001/

type: CLIENT

precondition: SELECT OS FROM info() WHERE OS = 'windows'

parameters:
  - name: KeyGlob
    description: Registry keys to read.
    default: |
      HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run*\*
      HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Run*\*
  - name: OnlyUnsigned
    type: bool
    description: Show only entries whose file is not signed.

resources:
  timeout: 300
  max_rows: 10000

sources:
  - name: Entries
    query: |
      LET entries = SELECT OSPath.Dirname AS Key, OSPath.Basename AS Name,
             Data.value AS Command
      FROM glob(globs=split(string=KeyGlob, sep="\n"), accessor="registry")

      SELECT *, authenticode(filename=Command).Trusted AS Signed
      FROM entries
      WHERE NOT OnlyUnsigned OR Signed != "trusted"
```

## The fields

| Field | Meaning |
|---|---|
| `name` | Unique name. Custom artifacts should start with `Custom.` |
| `description` | Markdown shown in the console and the reference. Say what it collects, when to use it, and what the columns mean |
| `author`, `reference` | Who wrote it and links to background (ATT&CK, blog posts) |
| `type` | `CLIENT` (default), `CLIENT_EVENT`, `SERVER`, `SERVER_EVENT` or `NOTEBOOK`; see [Artifacts](/artifacts/#kinds-of-artifacts) |
| `precondition` | A query that must return a row for the artifact to run. Usually an OS check |
| `parameters` | Inputs users can set; see [Parameters](/artifacts/parameters/) |
| `sources` | The queries. Each source produces one results table |
| `resources` | Default limits; see below |
| `tools` | External programs or files the artifact needs; see [Tools](/artifacts/tools/) |
| `required_permissions` | Permissions a user needs to collect it; see [Artifact security](/artifacts/security/) |
| `implied_permissions`, `impersonate` | Permissions the artifact's own queries get; see [Artifact security](/artifacts/security/) |
| `export` | VQL (usually `LET` definitions) that other artifacts can import |
| `imports` | Artifacts whose `export` to include before this artifact's queries |
| `column_types` | Hints for how the console shows columns (for example `timestamp`, `preview_upload`) |
| `aliases` | Other names the artifact can be collected by |

## Sources

Each source has a `query` (one or more VQL statements; the last `SELECT`
produces the rows), and optionally a `name`, its own `precondition` and a
`notebook` (cells to create in the collection's notebook).

Multiple sources are useful when an artifact collects several related
tables, such as `Users` and `Groups`. With a `name`, a source's results are
called `<Artifact>/<Source>`, for example `Generic.Client.Info/Users`.

A source with a precondition runs only if its precondition passes. That
makes one artifact work on several operating systems:

```yaml
sources:
  - precondition: SELECT OS FROM info() WHERE OS = 'windows'
    query: SELECT * FROM Artifact.Windows.System.Pslist()
  - precondition: SELECT OS FROM info() WHERE OS != 'windows'
    query: SELECT * FROM Artifact.Linux.Sys.Pslist()
```

## Resources {#resources}

```yaml
resources:
  timeout: 600            # seconds before the collection is stopped
  max_rows: 1000000       # rows in total
  max_upload_bytes: 1073741824
  cpu_limit: 50           # percent of one CPU
  ops_per_second: 0
```

These are defaults. A user can override them when starting a collection or
hunt. Set a longer `timeout` for artifacts that walk whole disks, and a
`max_upload_bytes` that fits the files you expect.

## Using other artifacts

Any artifact can be called from VQL like a plugin, with its parameters as
arguments:

```sql
SELECT * FROM Artifact.Windows.System.Pslist(ProcessRegex="powershell")
```

To reuse `LET` definitions instead of results, put them in `export` and
list the artifact under `imports` in the other artifact.

## Testing an artifact

1. **Check and save** reports YAML and VQL errors.
2. Collect it from one test machine and read the collection's **Log**: it
   shows each query, how long it took and any errors.
3. For quick iterations, run the query in a notebook first (a VQL cell
   runs on the server, so for client data use `collect_client()` or test
   on a client with the **VQL** shell).
4. On your workstation, `atlantiraptor artifacts collect` runs an artifact
   locally with the same engine (see [Command line](/cli/)):

   ```bash
   atlantiraptor -v artifacts collect Custom.Windows.Persistence.RunKeys \
       --definitions ./my-artifacts --args OnlyUnsigned=Y
   ```

`atlantiraptor artifacts verify` checks a folder of artifact files, and
`artifacts reformat` reformats them in the standard style.

## Style

- One artifact, one question. Several sources are fine; several unrelated
  questions are not.
- Give every column a clear name (`AS`), and keep names consistent with
  built-in artifacts (`OSPath`, `Size`, `Mtime`, `Username`, `Pid`).
- Filter on the client, with parameters, rather than sending everything
  to the server.
- Describe every parameter.

See [Tips](/artifacts/tips/) for performance patterns.
