---
title: Tools
description: How Atlantiraptor artifacts use external programs and data files, how the server downloads and serves them, and how to supply them on air-gapped networks.
---

Some artifacts need something besides VQL: a Sysinternals program, a
memory acquisition tool, a YARA rules file. These are **tools**. An
artifact declares the tools it needs, and Atlantiraptor gets them to the
endpoint when the artifact runs.

## Declaring a tool

```yaml
tools:
  - name: Autorun_amd64
    url: https://live.sysinternals.com/tools/autorunsc64.exe
    serve_locally: true
```

In the query, `Generic.Utils.FetchBinary` returns the local path of the
tool on the endpoint, downloading it if needed and checking its hash:

```sql
LET bin <= SELECT * FROM Artifact.Generic.Utils.FetchBinary(
    ToolName="Autorun_amd64")

SELECT * FROM execve(argv=[bin[0].OSPath, "-nobanner", "-a", "*", "-c"])
```

| Field | Meaning |
|---|---|
| `name` | The tool's name, unique on the server |
| `url` | Where to get it |
| `github_project`, `github_asset_regex` | Get the latest release asset from a GitHub project instead |
| `serve_locally` | `true`: the server downloads the file once and serves it to clients. `false`: each client downloads it from `url` |
| `expected_hash` | SHA-256 the file must have |
| `filename` | The file name on the endpoint |
| `version` | Informational |

## How tools reach endpoints

1. The first time an artifact with a tool is collected, the server
   downloads the tool (unless it already has it), records its SHA-256 hash
   and stores it.
2. The collection request tells the client where to get the tool (the
   server, or the original URL) and the hash it must have.
3. The client downloads it, checks the hash, and caches it. Later
   collections reuse the cached copy while the hash matches.

A tool that fails its hash check is not run.

## Air-gapped servers

A server that can't reach the internet can't download tools. Supply them
yourself:

- `Server.Utils.UploadTools`: first produces a script that downloads every
  tool on a connected machine, then, run again, uploads the downloaded
  files from a folder on the server into the tools inventory.
- The command line, on the server:

  ```bash
  atlantiraptor --config server.config.yaml tools upload \
      --name Autorun_amd64 autorunsc64.exe
  ```

- VQL: `inventory_add(tool="Autorun_amd64", file="/srv/tools/autorunsc64.exe")`.

To stop the server from downloading tools at all, set
`security.disable_inventory_service_external_access: true`; tools then
have to be uploaded as above.

Organizations each have their own tools inventory, so upload tools in
every org that needs them.

## Overriding a tool

To use a different version, or your own build, upload a file under the
tool's name as above. An uploaded tool is marked as overridden by an
administrator and is kept when the server is upgraded.

`atlantiraptor tools show` lists the tools the server knows, and
`inventory()` does the same in VQL.

## Third-party binaries

Tools are third-party software with their own licences. Atlantiraptor
downloads them from their publishers' sites; it does not ship them.
Check that their licences fit your use.
