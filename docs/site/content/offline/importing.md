---
title: Importing offline collections
description: Import offline collector results into the Atlantiraptor server, decrypt them, or read them without a server.
---

## Importing into the server

Import a collection to analyse it like any other: it appears as a
collection of a client, with its results, uploaded files, log and notebook.

1. Copy the zip to the server (for example with `scp`, or by
   uploading it to a folder the server can read).
2. Open **Server collections**, **Collect**, and pick
   `Server.Utils.ImportCollection`.
3. Set:
   - **Path**: the zip's path on the server,
   - **ClientId**: `auto` to create a new client for this machine, or an
     existing client ID to add the collection to that client,
   - **Hostname**: the machine's name, for a new client.
4. **Collect now**.

When it finishes, search for the host name. Its **Collections** list has
the imported collection.

Collections encrypted with your server's certificate (X509) are decrypted
during the import. For password-protected ones, import from a notebook after setting the
password:

```sql
LET ZIP_PASSWORDS <= "the password"
SELECT import_collection(filename="/data/Collection-WS-0142.zip",
                         hostname="WS-0142")
FROM scope()
```

Collections uploaded to S3, GCS or Azure have to be downloaded to the
server first. A server artifact that watches a bucket and imports what
arrives is a common automation; see [Server automation](/server-automation/).

## Automating after import

Every import emits a `System.Flow.Completion` event, like a finished
collection. A server event artifact that watches it can run follow-up
analysis automatically (for example, run Sigma rules over imported event
logs). See [Event queries](/vql/events/).

## Decrypting by hand

To open an X509-encrypted collection without importing it:

```bash
atlantiraptor --config server.config.yaml decrypt Collection-WS-0142.zip out.zip
```

The server configuration holds the private key, so do this on the server
or a machine as trusted as it.

## Reading a collection without a server

The `unzip` command reads a collection zip (including password-protected
ones with `--password`):

```bash
# list the files
atlantiraptor unzip --list Collection-WS-0142.zip
# extract everything into a folder
atlantiraptor unzip Collection-WS-0142.zip --dump_dir ./ws-0142
```

Results are JSON lines files under `results/`, one per artifact source,
which `jq`, Python or a spreadsheet (through `atlantiraptor csv`) can read.
See [The zip layout](/evidence/#the-zip-layout).
