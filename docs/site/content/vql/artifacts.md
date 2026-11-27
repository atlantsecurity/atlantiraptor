---
title: Artifacts in VQL
description: Call artifacts from VQL, start collections and hunts from queries, and read their results in Atlantiraptor.
---

Artifacts and VQL work in both directions: an artifact is VQL, and VQL can
call artifacts, start collections and read results.

## Calling an artifact like a plugin

Every artifact is available as `Artifact.<name>()`, with its parameters as
arguments. It runs right there, in the current query, on the machine where
the query runs:

```sql
SELECT Name, Pid, Hash.SHA256 AS SHA256
FROM Artifact.Windows.System.Pslist(ProcessRegex="rundll32")
```

For an artifact with several sources, pick one with `source=`:

```sql
SELECT * FROM Artifact.Generic.Client.Info(source="Users")
```

This is the main way to build on existing work: your artifact can call a
built-in one and add a filter, a join, or an alert.

## Collecting from clients

On the server (notebooks, server artifacts), `collect_client()` schedules a
collection on a client and returns at once with the new collection's ID:

```sql
SELECT collect_client(
    client_id="C.1a2b3c4d5e6f7a8b",
    artifacts=["Windows.System.Pslist", "Windows.Network.Netstat"],
    urgent=TRUE) AS Collection
FROM scope()
```

Parameters go in `spec`, one dict per artifact:

```sql
spec=dict(`Windows.System.Pslist`=dict(ProcessRegex="rundll32"))
```

Results arrive when the client has run it. To act on them, watch
`System.Flow.Completion` (see [Event queries](/vql/events/)).

`hunt()` creates a hunt in the same way, with `include_labels`,
`exclude_labels`, `expires` and `pause`.

## Collecting locally into a zip

`collect()` runs artifacts on the current machine and writes a collection
zip, the same format as the [offline collector](/offline/):

```sql
SELECT * FROM collect(artifacts="Generic.Client.Info",
                      output="/tmp/collection.zip")
```

## Reading results

| Read | With |
|---|---|
| A collection's results | `source(client_id=…, flow_id=…, artifact=…)` |
| A hunt's results | `hunt_results(hunt_id=…, artifact=…)` |
| Monitoring data | `source(client_id=…, artifact=…, start_time=…, end_time=…)` |
| The list of collections | `flows(client_id=…)` |
| The list of hunts | `hunts()` |
| A collection's uploaded files | `uploads(client_id=…, flow_id=…)` |
| Clients | `clients(search=…)` |

Inside a collection's or hunt's notebook, `source()` without IDs reads the
current one.

## Artifact definitions

`artifact_definitions(names=…)` returns artifacts' definitions, which is
handy for inventories ("which artifacts need EXECVE?"):

```sql
SELECT name, type, required_permissions
FROM artifact_definitions()
WHERE "EXECVE" IN required_permissions
```
