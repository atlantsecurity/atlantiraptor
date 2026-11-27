---
title: Storage and data retention
description: Where Atlantiraptor keeps its data, how much space it needs, and how to delete old data.
---

## The datastore

The server keeps everything in two directories, set in the configuration:

- `Datastore.location`: small files, such as client records, flow and
  hunt metadata, user records, notebook definitions.
- `Datastore.filestore_directory`: large files, such as result sets
  (JSON lines), uploaded files, monitoring logs and exports.

They are usually the same directory. Everything is plain files: there is
no database server to run. Inside, data is organised per organization
(`orgs/<org id>/` for orgs other than root), then by client, flow, hunt
and so on. Notable locations:

| Path (under the datastore) | Contents |
|---|---|
| `clients/<client id>/collections/<flow id>/` | One collection: results, logs, uploads |
| `clients/<client id>/monitoring/<artifact>/` | Client event data, one file per day |
| `server_artifacts/<artifact>/` | Server event data, per day |
| `hunts/` | Hunt definitions and statistics |
| `notebooks/` | Notebooks, cells and exports |
| `downloads/` | Prepared zip exports of hunts and collections |
| `users/` | User records, preferences, two-factor records |
| `config/` | Server-side settings (network access, API keys, groups, update settings) |

Files are written by the server process only. Do not edit them while the
server runs.

## How much space

What uses space:

- **Monitoring** artifacts that run on every endpoint all the time (for
  example process creation or DNS events) are the largest consumers over
  time. Estimate *events per endpoint per day × endpoints × days kept*.
- **Hunts that upload files** (event logs, memory, MFT) can add gigabytes
  per endpoint in one go.
- **Exports** of hunts and collections (zip files) duplicate data.

`Server.Utils.StorageAnalysis` (a server artifact) lists every file in the
datastore, and its notebook breaks storage down per client, per artifact
and per hunt, so you can see what uses the most space.

The server stops writing when free space drops below
`Datastore.min_allowed_file_space_mb` (50 MB by default), to avoid
corrupted files. Keep well above that: monitor the disk and alert at 80%.

## Deleting old data

Atlantiraptor does not delete data by itself. Choose a retention period and
delete older data regularly:

| What | How |
|---|---|
| A collection | **Collections**, select it, **Delete**; or `Server.Utils.DeleteFlow` / `Server.Utils.DeleteManyFlows` |
| A hunt and its collections | **Hunts**, select, **Delete** |
| Old monitoring data | `Server.Utils.DeleteMonitoringData` (by artifact and date range); or `Server.Utils.DeleteEvents` |
| A client and all its data | **Clients**, select, **Delete**; or `Server.Utils.DeleteClient` |
| A notebook | **Notebooks**, open, **Delete notebook** |
| Exports | Delete them from the hunt or collection's export list |

Deleting is permanent. The `Server.Utils.Delete*` artifacts have a
**ReallyDoIt** parameter: run them first without it to see what would be
removed.

### Automating retention

Schedule a server artifact that deletes data older than your retention
period. A simple approach is a custom `SERVER_EVENT` artifact that runs
`clock()` once a day and calls the delete artifacts for data older than N
days, or use your operating system's scheduler with the command line
(`atlantiraptor --api_config api.config.yaml query ...`). See
[Server automation](/server-automation/).

### Clients that are gone

**Fleet health** lists clients not seen for 7 or 30 days. Delete those that
were decommissioned, so hunts do not wait for them and the client list
stays useful.

## Moving the datastore

1. Stop the server.
2. Copy the directory to the new location, preserving permissions.
3. Change `Datastore.location` and `filestore_directory`.
4. Start the server.

## Shared and cloud storage

The datastore can live on a network file system shared by several
frontends (see [Scaling out](/deployment/scaling/)). It needs low latency
and correct file locking; NFS v4 and Amazon EFS work. SMB shares and
object-storage mounts (such as S3 file systems) are not suitable for the
live datastore, but are fine for [backups](/deployment/backups/) and for
[offline collection uploads](/offline/running/#sending-results-somewhere).
