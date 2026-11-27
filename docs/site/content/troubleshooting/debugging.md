---
title: Debugging and profiling
description: Verbose logs, VQL tracing, the debug server and profiling artifacts for finding out what an Atlantiraptor agent or server is doing.
---

When a log message is not enough, Atlantiraptor can tell you in detail what
it is doing: which queries run, where time and memory go, and what each
goroutine is waiting for. Use these tools to diagnose a problem yourself,
or to collect data for [support](/support/).

## Verbose logging

Add `-v` to any command to print detailed logs to the console:

```text
Atlantiraptor.exe --config client.config.yaml client -v
atlantiraptor --config server.config.yaml frontend -v
```

To debug an installed Windows agent, stop the service first, then run the
agent in a console window as an administrator with the same configuration
file. It connects to the server as usual and prints every step: loading its
configuration, connecting, enrolling and running queries.

## Tracing VQL

`--trace_vql` logs each VQL query as it runs, with the plugins and
functions it calls. Combine it with `-v` and the `query` command to see why
a query behaves as it does:

```text
atlantiraptor query --trace_vql -v "SELECT * FROM pslist() LIMIT 1"
```

In notebooks and artifacts, `log()` prints a message into the query log,
which is often quicker (see [Troubleshooting VQL](/troubleshooting/vql/)).

## The debug server

Start the server or agent with `--debug` to open a debug web server on
`http://127.0.0.1:6060/debug/pprof` (change the port with `--debug_port`).
It listens only on the loopback interface. It shows:

- the running goroutines with their stack traces,
- heap and allocation profiles,
- CPU profiles and execution traces, which you read with `go tool pprof`,
- internal state such as running queries and service status.

Do not leave it on in production: it costs some memory and shows internals
to anyone who can reach the port on that machine.

## Profiling a running agent

You don't need to restart an agent to profile it. Collect
`Generic.Client.Profile` from the host:

| Parameter | Collects |
|---|---|
| **Goroutine** (default) | Stack traces of all goroutines: what the agent is busy with |
| **Allocs** (default) | Where memory has been allocated |
| **Heap** | Memory in use now |
| **Profile** | A CPU profile over the **Duration** |
| **Trace** | An execution trace |
| **Block**, **Mutex** | Where goroutines wait on locks |
| **Logs**, **QueryLogs** | The agent's recent log and recent queries |
| **Metrics** | The agent's internal counters |

Run it while the slow collection or monitoring query is running, otherwise
there is little to see. Profiles are uploaded as files; read them with:

```text
go tool pprof -http=:8080 profile.bin
```

## Profiling the server

`Server.Monitor.Profile` collects the same data from the server. Run it
from **Server collections** (it needs the `COLLECT_SERVER` permission).

For the overall picture first, the server's own CPU and memory use is
recorded by the `Server.Monitor.Health` server event artifact, and
[Fleet health](/console/fleet-health/) shows agents that went quiet or keep
failing.

## Tracing a collection

When a collection takes far longer than expected, set **Trace Frequency
Seconds** in its **Resources** (10, 30 or 60 seconds). The agent then runs
`Generic.Client.Trace` alongside it and uploads a snapshot of its goroutines
and memory at that interval, until the collection ends. You can read the
snapshots from the collection's **Files** tab to see where it was stuck.

If you add `Generic.Client.Trace` to a collection yourself, cancel it by
hand: it runs until the collection's timeout.

## What to send to support

When you report a problem, include:

- the version (**Server updates** page, or `atlantiraptor version`),
- the exact error and the collection's **Log** tab,
- a `-v` log from the agent or server around the time of the problem,
- for performance problems, a `Generic.Client.Profile` or
  `Server.Monitor.Profile` collection with **Goroutine**, **Heap** and a
  30-second **Profile**.

Remove host names, user names and secrets from logs before you send them.
