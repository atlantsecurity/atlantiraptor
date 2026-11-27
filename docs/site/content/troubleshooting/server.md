---
title: Server problems
description: Fix Atlantiraptor server problems - collections that return nothing, a slow console, high CPU or memory, a full disk, and a server that won't start.
---

## Collections that return nothing {#collections-that-return-nothing}

Open the collection and read its **Log** tab first. Then:

| What you see | Cause and fix |
|---|---|
| State stays **Scheduled** | The client is offline; it runs when the client connects |
| Finished, 0 rows, no errors | The artifact found nothing. Check the parameters (globs, regexes, time window), and that the precondition matches the OS: the log says when a source was skipped |
| "Permission denied" or access errors | The agent can't read the file: use the `ntfs` or `auto` accessor for locked files. On macOS, give the agent Full Disk Access |
| Stopped at a timeout | Raise the timeout, narrow the search, or set a CPU limit that isn't too low |
| Stopped at a row or upload limit | Raise `max_rows` or `max_upload_bytes`, or filter more on the client |
| "artifact not found" | The artifact doesn't exist on the server (a pack that wasn't imported, a renamed artifact), or the client is too old for it |
| Tool download errors | The server or the client can't download a [tool](/artifacts/tools/); upload it by hand on air-gapped networks |
| "Permission denied" when starting | Your role lacks a permission the artifact requires; see [Permissions](/users/permissions/) |

For hunts, the **Errors** tab lists failing clients, and the **Clients**
tab shows which clients were scheduled at all. If none were, check the
hunt's targeting (labels, OS, last seen).

## The console is slow

- Look at the server's CPU, memory and disk on the dashboard and with
  `Server.Monitor.Health`.
- Large notebooks and result tables are slow to render; filter in VQL and
  use `LIMIT`.
- Long notebook cells and server artifacts compete with the console; see
  [Notebooks and server queries](/deployment/performance/#notebooks-and-server-queries).
- Many concurrent hunts collecting lots of data load the server; see
  [Load on the server from hunts](/deployment/performance/#load-on-the-server-from-hunts).

## High CPU or memory

1. Find what's running: **Server events** (monitoring artifacts), running
   server collections, and notebooks.
2. Check the client event artifacts: too many events from many clients
   costs server CPU to store and process.
3. Collect `Server.Monitor.Profile` while it happens, or start the server
   with `--debug` (see [Debugging](/troubleshooting/debugging/)).

## "Received message larger than max" {#message-too-large}

The console or an API call fails with *received message larger than max*
when a single response from the server's internal API is over the limit,
4 MB by default. It usually means one result holds very large values, for
example a whole file read into a column, or a notebook cell or table page
with very wide rows.

- Return less per row: upload large content with `upload()` instead of
  putting it in a column, and select only the columns you need.
- Page through results with `LIMIT`, or split a large query.
- If you really need larger responses, raise `api_config.max_grpc_recv_size`
  in the server configuration, or in the API client's configuration for
  [gRPC API](/server-automation/grpc-api/) clients.

The datastore has a similar cap for each object it stores,
`Datastore.max_object_size` (4 MB). Hitting it means a single stored item
(such as an artifact definition or notebook cell) has grown too big: split
it rather than raising the limit.

## The disk is filling up

Monitoring data and uploaded files grow without limit unless you delete
them. See [How much space](/deployment/storage/#how-much-space) and
[Deleting old data](/deployment/storage/#deleting-old-data).
`Server.Utils.StorageAnalysis` shows what uses the space.

## The server won't start

Run it in a terminal to see the error:

```bash
atlantiraptor --config server.config.yaml frontend -v
```

| Error | Fix |
|---|---|
| `bind: address already in use` | Another program (or a second server) uses the port. Stop it or change the port in the configuration |
| permission denied on the datastore | The service account can't write `Datastore.location`; fix the folder's owner |
| configuration parse errors | YAML indentation or a typo; compare with `config show` of a working copy |
| certificate expired | Reissue the certificates; see [TLS](/deployment/tls/#renewing-the-internal-certificates) |

On Linux, `journalctl -u velociraptor_server` shows the service's output.
On Windows, look in the server log directory and the Windows event log.

## Users can't sign in

See [Authentication](/deployment/authentication/) for passwords,
two-factor sign in and single sign-on, and
[If you lock yourself out](/deployment/network-access/#if-you-lock-yourself-out)
when the network allowlist blocks you.
