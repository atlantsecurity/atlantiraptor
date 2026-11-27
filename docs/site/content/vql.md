---
title: VQL
description: VQL, the query language behind every Atlantiraptor artifact, collection and notebook - what it is and where to start.
---

**VQL** (the Velociraptor Query Language, which Atlantiraptor inherits) is
how everything in Atlantiraptor gets done. Artifacts are VQL queries;
notebooks run VQL over collected data; server automation is VQL that
watches event queues. You don't need VQL to use the console, but knowing
it lets you write your own artifacts and answer questions no built-in
artifact covers.

VQL looks like SQL, but it queries the live machine rather than a database:

```sql
SELECT Name, Pid, CommandLine
FROM pslist()
WHERE Name =~ "powershell"
```

`pslist()` is a **plugin** that returns one row per running process. The
query filters the rows and picks columns. There are plugins for files,
the registry, event logs, network connections, ETW, memory, cloud APIs
and much more, and **functions** that compute values (`hash()`,
`authenticode()`, `parse_json()`, `timestamp()`).

## Where VQL runs

| Where | Runs on | Typical use |
|---|---|---|
| Client artifacts (collections, hunts) | The endpoint | Collecting evidence |
| Client event artifacts | The endpoint, continuously | Monitoring |
| Notebooks | The server | Analysing collected results |
| Server artifacts and server events | The server | Automation, integrations, cloud hunting |
| The **VQL** shell | The endpoint | Trying a query on one host |
| `atlantiraptor query` | Your own machine | Learning, testing, live response on a machine without a server |

## Trying VQL

The quickest way to learn is the command line on your own machine:

```bash
atlantiraptor query "SELECT * FROM info()"
atlantiraptor query "SELECT Name, Pid FROM pslist() LIMIT 5" --format csv
```

In the console, a notebook VQL cell runs on the server, and the
**VQL** shell runs a query on a client.

## In this section

- [Fundamentals](/vql/fundamentals/): the syntax, step by step.
- [Advanced VQL](/vql/advanced/): subqueries, `foreach`, aggregation,
  lazy evaluation, custom functions and performance.
- [Event queries](/vql/events/): queries that never end, and server
  automation with `watch_monitoring()`.
- [Artifacts in VQL](/vql/artifacts/): calling artifacts from queries and
  collecting from VQL.
- [Sigma](/vql/sigma/) and [YARA](/vql/yara/): detection rules in VQL.
- The [VQL reference](/reference/vql/): every plugin, function and
  accessor, with its arguments.
