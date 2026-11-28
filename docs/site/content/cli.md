---
title: Command line
description: The atlantiraptor command - running the server and client, configuration, packages, users, artifacts, queries and forensic tools from the command line.
---

The same `atlantiraptor` binary is the server, the client, the offline
collector and a forensic command-line tool. Run it with no arguments, or
`atlantiraptor help`, for the list of commands; `atlantiraptor help
<command>` explains one. The [CLI reference](/reference/cli/) lists every
command and flag, generated from the binary itself.

On Windows the binary is `Atlantiraptor.exe`. Linux packages install it as
`velociraptor` (the package and service names kept from the upstream
project, so existing deployments upgrade in place).

## Global flags

| Flag | Meaning |
|---|---|
| `--config`, `-c` | The configuration file (server or client) |
| `--api_config`, `-a` | An API client configuration: run the command against a server through the [gRPC API](/server-automation/grpc-api/) |
| `--org` | The organization to work in |
| `-v`, `--verbose` | Detailed logs |
| `--definitions`, `-D` | Also load artifacts from this folder |
| `--remap` | A [dead disk](/forensics/deaddisk/) remapping file |
| `--tempdir` | Where to write temporary files |
| `--logfile` | Also write logs to this file |

## Commands by task

### Running

| Command | Does |
|---|---|
| `frontend` | Runs the server: the client frontend, the console and the APIs |
| `client` | Runs the client (agent) |
| `gui` | Starts a throwaway server and client on this machine and opens the console, for a quick look only. Its agent runs as the user who started it, not as SYSTEM, so it can't see everything; install servers with `server_service install` and agents as a service (see [Deploying agents](/deployment/clients/)) |

### Configuration and deployment

| Command | Does |
|---|---|
| `config generate` | A new server configuration, with new keys (`-i` asks questions) |
| `config show` | The effective configuration |
| `config client` | The client configuration that goes with a server configuration |
| `config api_client` | An API client configuration |
| `config rotate_keys`, `config reissue_certs` | Renew the server's keys or certificates; see [TLS](/deployment/tls/#renewing-the-internal-certificates) |
| `config repack` | Embed a configuration into the binary, so it runs without a separate file |
| `debian server`, `debian client`, `rpm server`, `rpm client` | Linux packages; see [Deploying clients](/deployment/clients/) |

### Users and access

| Command | Does |
|---|---|
| `user add`, `user show` | Create a user or change a password; show a user |
| `acl show`, `acl grant` | Show or set a user's roles and permissions |

### Artifacts and VQL

| Command | Does |
|---|---|
| `query` | Run VQL; see [Queries and collections](/cli/collector-and-query/) |
| `artifacts list`, `artifacts show` | List artifacts, show one's definition |
| `artifacts collect` | Run artifacts on this machine |
| `artifacts verify`, `artifacts reformat` | Check and reformat artifact files |
| `artifacts fetch` | Download a collection from a server through the API |
| `vql list`, `vql export` | List or export the VQL plugins and functions |
| `lsp` | A VQL language server, for editor support |
| `tools show`, `tools upload`, `tools rm` | Manage the server's [tools](/artifacts/tools/) |

### Offline collection and evidence

| Command | Does |
|---|---|
| `collector` | Build an [offline collector](/offline/building/) from a spec file |
| `unzip` | Read or extract a collection zip |
| `decrypt` | Decrypt an X509-encrypted collection with the server's key |
| `deaddisk` | Build a remapping for a disk image |
| `csv` | Convert CSV to JSON or other formats |
| `fs` | Browse and copy from the server's file store (`fs ls`, `fs cp`, `fs cat`) |
| `fuse container` | Mount collection zips as a folder (Linux and macOS) |

### Maintenance

| Command | Does |
|---|---|
| `version` | Version and build information |
| `hunts reconstruct` | Rebuild hunt records from their logs after datastore damage |
| `golden` | Run artifact tests against expected output (for developers) |

On Windows and macOS, `service install`, `service remove`, `service
start` and `service stop` manage the client as a system service (the MSI
and the macOS installer do this for you). On Windows, `server_service
install` and `server_service remove` do the same for the server.
