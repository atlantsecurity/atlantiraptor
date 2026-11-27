---
title: Server configuration
description: Create, read and change the Atlantiraptor server and client configuration files.
---

Atlantiraptor reads its settings from YAML files. The **server
configuration** (`server.config.yaml`) holds everything: the server's
keys, its addresses, the datastore location, sign-in settings and the
agent settings. The **client configuration** (`client.config.yaml`) is
the subset that agents need. It contains no secrets except the CA
certificate that agents use to recognise the server.

Every setting is listed in the [configuration file reference](/reference/config/).

## Creating a configuration

### With the wizard

```sh
atlantiraptor config generate -i
```

The wizard asks:

- which operating system the server will run on (this sets default
  paths),
- where to keep the datastore and logs,
- how agents will verify the server: self-signed certificates, Let's
  Encrypt, or single sign-on with Let's Encrypt,
- the public DNS name (or IP address, for self-signed certificates) and the
  ports for the frontend and the console,
- whether to use dynamic DNS,
- the first console users and their passwords,

and writes both files. Generate the configuration once per deployment:
the CA it creates is what ties the agents to this server.

### Without the wizard

`config generate` without `-i` prints a configuration with new keys and
default values. Combine it with `--merge` (a JSON merge patch, RFC 7396) to
set values in the same step, which is useful in scripts:

```sh
atlantiraptor config generate --merge '{
  "Frontend": {"hostname": "atlantiraptor.example.com", "bind_port": 443},
  "Client": {"server_urls": ["https://atlantiraptor.example.com/"]},
  "Datastore": {"location": "/data/atlantiraptor", "filestore_directory": "/data/atlantiraptor"}
}' > server.config.yaml
```

`--merge_file` reads the patch from a file, and `--patch` / `--patch_file`
apply a JSON Patch (RFC 6902) instead.

## Reading the configuration

```sh
atlantiraptor --config server.config.yaml config show          # YAML
atlantiraptor --config server.config.yaml config show --json   # JSON
atlantiraptor --config server.config.yaml config client > client.config.yaml
```

`config show` accepts the same `--merge` and `--patch` options, so you can
change a configuration without editing it by hand:

```sh
atlantiraptor --config server.config.yaml config show \
  --merge '{"GUI": {"bind_address": "0.0.0.0"}}' > server.new.yaml
```

`config client` writes the client configuration for the current server
configuration. Run it again after you change anything under `Client` (for
example the server URLs) and redeploy agents with the new file.

## Changing the configuration

1. Back up the current file.
2. Edit it (or use `config show --merge`).
3. Check it: `atlantiraptor --config server.config.yaml config show > /dev/null`
   reports syntax errors.
4. Restart the server.

Settings you will commonly change:

| Setting | What it does |
|---|---|
| `Client.server_urls` | Where agents connect. A list; agents try each in turn. |
| `Frontend.hostname`, `Frontend.bind_port` | The frontend's name and port. |
| `GUI.bind_address`, `GUI.bind_port` | Where the console listens. `127.0.0.1` keeps it local (behind a reverse proxy). |
| `GUI.public_url` | The console's URL as users reach it, used in links and sign-in redirects. |
| `GUI.authenticator` | How users sign in. See [Authentication](/deployment/authentication/). |
| `GUI.links` | Extra links in the console sidebar, such as your wiki. |
| `Datastore.location`, `Datastore.filestore_directory` | Where data is kept. |
| `Logging` | Log files and rotation. See [Server logging](/deployment/logging/). |
| `Defaults` | Limits and defaults, for example `hunt_expiry_hours` (1 in Atlantiraptor). |
| `Frontend.proxy` | Proxy for the server's own outgoing connections (tools, cloud APIs, updates). |

## Configuration from the environment

Instead of `--config`, you can point the program to its configuration with
environment variables, which is convenient in containers and services:

| Variable | Meaning |
|---|---|
| `VELOCIRAPTOR_CONFIG` | Path of the configuration file. |
| `VELOCIRAPTOR_LITERAL_CONFIG` | The configuration itself, as YAML text. |
| `VELOCIRAPTOR_API_CONFIG` | Path of an API client configuration, for the [gRPC API](/server-automation/grpc-api/). |

Atlantiraptor adds a few switches of its own, read when the server starts:

| Variable | Effect |
|---|---|
| `ATLANTIRAPTOR_DISABLE_MFA=1` | Turns the two-factor check off (break-glass when every administrator lost their factor). |
| `ATLANTIRAPTOR_DISABLE_ALLOWLIST=1` | Turns the [network access lists](/deployment/network-access/) off. |
| `ATLANTIRAPTOR_DISABLE_AUTO_UPDATE=1` | Stops [automatic server updates](/deployment/updates/) from installing. |

## Rotating keys and certificates

The server's own certificate is valid for one year by default. Renew it
before it expires:

```sh
atlantiraptor --config server.config.yaml config reissue_certs --validity 365 > server.new.yaml
```

This keeps the CA and the server key and issues new certificates. Agents do
not notice. To replace the server key as well (for example after the
configuration may have leaked), use `config rotate_keys`. Agents keep
working because they trust the CA, not the key.

The server warns in its log when the certificate is close to expiry. See [TLS certificates](/deployment/tls/#renewing-the-internal-certificates).

## Keeping secrets out of the file

The configuration contains the CA private key (`CA.private_key`), which is
needed to sign new API client certificates and to issue new server
certificates, but not to run the server. A high-security deployment can
remove it from the running server's file and keep a full copy offline.

Credentials for cloud tenants, SIEMs and mail servers do not belong in the
configuration: store them as [secrets](/secrets/).

## Repacking agents with a configuration

Agents on Windows normally get their configuration from the
[MSI](/deployment/clients/#windows). You can also embed a configuration
into the binary itself, so that a single file is enough:

```sh
atlantiraptor config repack client.config.yaml Atlantiraptor-agent.exe
```

`--exe` uses another binary (for example a different architecture), and
`--binaries` adds tools to the package for offline use. A repacked binary
is no longer signed; sign it again before you distribute it.
