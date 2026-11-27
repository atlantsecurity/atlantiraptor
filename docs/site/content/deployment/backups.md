---
title: Backups and disaster recovery
description: What to back up on an Atlantiraptor server, how, and how to restore or move a server.
---

## What to back up

1. **The server configuration file.** It contains the CA and server keys.
   Without it, you cannot run a server that your existing agents trust: you
   would have to redeploy every agent. Back it up once, keep copies offline,
   and again after you rotate keys.
2. **The datastore** (`Datastore.location` and
   `Datastore.filestore_directory`): client records, results, hunts,
   notebooks, cases, users, custom artifacts and settings.

Agents themselves need no backup. If the server is rebuilt with the same
configuration, they reconnect and send any results they queued while it was
down.

## Backing up the datastore

The datastore is plain files, so any file-level backup works. For a
consistent copy:

- **Snapshots** (recommended): a volume snapshot (LVM, ZFS, cloud disk
  snapshot, Windows VSS) taken while the server runs is consistent enough;
  the server tolerates restoring from one.
- **File copy**: stop the server, copy the directory, start it again. Or
  copy it live with `rsync` / `robocopy` and accept that the newest few
  minutes may be partial.

Exclude `downloads/` (exports can be rebuilt) and temporary folders to
save space.

### Copying results as they arrive

Three server event artifacts keep an extra copy of every finished
collection's results outside the datastore. Enable them under **Server
events**; they complement, but do not replace, a datastore backup:

| Artifact | Does |
|---|---|
| `Server.Utils.BackupDirectory` | Exports each completed collection to a folder on the server |
| `Server.Utils.BackupS3` | Zips and uploads each completed collection to an S3-compatible bucket |
| `Server.Utils.BackupGCS` | The same, to Google Cloud Storage |

Each takes an artifact name regex, so you can copy only what matters (for
example triage collections).

## Restoring

1. Install the same version of Atlantiraptor (or newer) on the new machine.
2. Restore the configuration file.
3. Restore the datastore to the path in the configuration.
4. If the machine's address changed, point the DNS name in
   `Client.server_urls` to it. Agents find the server by name.
5. Start the server and check that agents reconnect.

## Moving a server

Moving is a restore onto a new machine: copy the configuration and
datastore, then switch DNS. If the DNS name must change too, add the new URL
to `Client.server_urls`, push the new client configuration to agents (for
example with a new MSI) while the old server still runs, and only then turn
the old one off.

## Disaster recovery without a backup of the configuration

If the configuration is lost, agents will not talk to a new server, because
it has a different CA. Generate a new configuration, deploy new agents
(the MSI upgrade replaces the configuration), and remove the old agents.
Their old data is lost unless the datastore survived.
