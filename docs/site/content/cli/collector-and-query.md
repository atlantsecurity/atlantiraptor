---
title: Queries and collections on the command line
description: Use the atlantiraptor binary on its own for live response and forensics - run VQL, collect artifacts into a zip, and query a server through the API.
---

The binary works without a server. On any machine you can run VQL and
artifacts directly, which is useful for live response on a machine with no
agent, for testing artifacts, and for analysing collected evidence on your
workstation.

## Running VQL

```bash
atlantiraptor query "SELECT Name, Pid, CommandLine FROM pslist() WHERE Name =~ 'ssh'"
```

| Flag | Meaning |
|---|---|
| `--format` | `json` (default), `jsonl`, `csv` or `text` |
| `--env Name=Value` | Set a variable for the query (repeatable) |
| `--max_wait` | Seconds to batch rows before printing (for event queries) |
| `--timezone` | Time zone for times printed as text |

Several statements can be given in one string, or several strings:

```bash
atlantiraptor query "LET x <= SELECT * FROM info()" "SELECT x.Hostname FROM scope()"
```

On Windows, quote the query with double quotes and use single quotes
inside it.

Run it as administrator (or root) for anything that reads protected
files, other users' processes or raw disks.

## Collecting artifacts into a zip

```bash
atlantiraptor -v artifacts collect Windows.System.Pslist Windows.Network.Netstat \
    --output triage.zip
```

| Flag | Meaning |
|---|---|
| `--args Name=Value` | Set an artifact parameter (repeatable) |
| `--output` | Write a collection zip (the same format as [offline collections](/offline/) and exports) |
| `--format` | Print results as `json`, `csv` or `csv_only` instead |
| `--definitions` | Load your own artifacts from a folder |

The zip can be [imported](/offline/importing/) into the server. Without
`--output`, results are printed.

`atlantiraptor artifacts list` lists the artifacts, and `artifacts show
<name>` prints one's definition.

## Analysing evidence offline

The accessors work on files you collected, so the forensic parsers are
available on your workstation:

```bash
# Every logon event in a collected Security.evtx
atlantiraptor query --format csv "
  SELECT System.TimeCreated.SystemTime AS Time,
         EventData.TargetUserName AS User, EventData.IpAddress AS IP
  FROM parse_evtx(filename='Security.evtx')
  WHERE System.EventID.Value = 4624"

# Read inside a collection zip without extracting it
atlantiraptor query "SELECT OSPath, Size FROM glob(globs='/**', root='Collection-WS-0142.zip', accessor='collector')"
```

## Working against a server

With an [API client configuration](/server-automation/grpc-api/), the
same commands run on the server instead:

```bash
# VQL on the server, with the API client's permissions
atlantiraptor --api_config api.config.yaml query "SELECT * FROM hunts() LIMIT 5"

# Download a collection
atlantiraptor --api_config api.config.yaml artifacts fetch --client_id C.1a2b3c4d5e6f7a8b \
    --flow_id F.CQ7K2V8E9N2A4 --output collection.zip
```

## Building collectors

`atlantiraptor collector spec.yaml` builds an offline collector from a
spec file; see [Building a collector](/offline/building/#with-the-command-line).
