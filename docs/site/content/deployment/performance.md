---
title: Performance and sizing
description: Size an Atlantiraptor server, monitor its health, and limit the load collections put on endpoints.
---

## Sizing the server

Rough starting points for a single server:

| Endpoints | CPU cores | Memory | Disk (to start) |
|---|---|---|---|
| up to 1,000 | 2 | 4 GB | 100 GB SSD |
| up to 5,000 | 4 | 8 GB | 250 GB SSD |
| up to 15,000 | 8 | 16 GB | 500 GB+ SSD |
| more | see [Scaling out](/deployment/scaling/) | | |

What matters most:

- **Disk speed.** The datastore writes many small files. Use SSD storage;
  network file systems are slower.
- **Disk size** grows with monitoring artifacts and file collection (see
  [Storage](/deployment/storage/#how-much-space)).
- **Memory** grows with connected agents and with large notebooks.
- **CPU** is used by TLS for agent connections, by hunts that many agents
  answer at once, and by notebooks and server artifacts.

## Monitoring the server

- **Dashboard > Server health** shows CPU and memory use and connected
  clients over time, sampled by the `Server.Monitor.Health` server event
  artifact.
- **Fleet health** shows agents that went quiet and hunts with failing
  clients.
- **Prometheus metrics** are served at `http://127.0.0.1:8003/metrics`
  (`Monitoring.bind_address` and `bind_port`). Point Prometheus, Grafana or
  Datadog at it, after binding it to an interface your scraper can reach.
  Useful metrics include connected clients, in-flight requests, upload
  rates and query counts.
- The [debug server](/troubleshooting/debugging/) shows live internals
  when you need to look deeper.

Alert when disk space runs low, when connected clients drop sharply, and
when the server restarts unexpectedly.

## Load on endpoints

Every collection has resource limits, so a hunt cannot slow down the
fleet. Set them in **New hunt** or **Collect** (the resource fields under
the parameters), and give artifacts their own defaults with a `resources`
section (see [Writing artifacts](/artifacts/writing/#resources)):

| Limit | Meaning | Default |
|---|---|---|
| CPU limit (%) | Average share of the CPU the query may use | none |
| Timeout (s) | Stop the query after this many seconds | 600 |
| Max rows | Stop after this many result rows | 1,000,000 |
| Max upload (MB) | Stop after uploading this much | 1024 |

When a limit is reached the collection stops and says why in its log.
Increase limits for big collections (memory images, full MFT) and lower the
CPU limit for hunts on busy servers.

While the server is unreachable, agents keep results in a local buffer
(`Client.local_buffer`) up to its configured size, and send them when the
connection returns.

## Load on the server from hunts

When thousands of agents answer a hunt at once, the server receives many
uploads in a short time. To spread the load:

- Target hunts with labels instead of all clients when you can.
- Avoid uploading files in a fleet-wide hunt unless needed; collect file
  metadata and hashes first, then upload from the hosts that matter.
- Try a new or heavy artifact on one or two clients, or a test label,
  before running it on everyone.
- Use the frontend's concurrency setting (`Frontend.resources.concurrency`)
  to limit how many agent requests are processed at once.

## Notebooks and server queries

Notebook cells and server artifacts run on the server. A cell that reads
millions of rows can take a lot of memory and time. Cells stop after 10
minutes by default (`defaults.notebook_cell_timeout_min`). Filter early in
the query, use `LIMIT` while developing, and see
[Notebooks](/notebooks/#long-running-cells) for more.
