---
title: Building a collector
description: Build an Atlantiraptor offline collector for Windows, Linux or macOS, with artifacts, encryption and an upload target.
---

Collectors are built on the server by the `Server.Utils.CreateCollector`
server artifact. You can run it from the console's builder, as a server
collection, or with the `collector` command.

## With the builder

The builder is a step-by-step form in the classic console view. Open
**Server collections** in the classic view (the address ends in
`#/classic/collected/server`) and click **Build offline collector**:

1. **Select Artifacts**: the artifacts to collect.
2. **Configure Parameters**: each artifact's parameters.
3. **Configure Collection** (the collector's settings, below).
4. **Specify Resources**: CPU limit, timeout, and so on.
5. **Review** and **Launch**.

The build runs as a server collection. When it finishes, the collector is
in that collection's **Files** tab, named `Collector_<binary>` (or the
name you chose). Download it from there.

## As a server collection

Under **Server collections**, **Collect** `Server.Utils.CreateCollector`
and set its parameters directly: `OS`, `artifacts` (a JSON list of names),
`parameters` (a JSON object of artifact name to parameters), `target`,
`encryption_scheme` and the `opt_*` options below.

## The collector's settings

| Setting | Meaning |
|---|---|
| **Target Operating System** | Windows, Windows on Arm, Linux, macOS (Intel or Apple silicon), or Generic |
| **Encryption Scheme** | **None**, **X509 Certificate/Frontend Cert** (default certificate is your server's) or **Password** |
| **Collection Type** | Where results go: **Zip Archive**, **S3 Bucket**, **Google Cloud Bucket**, **Azure SAS URL**, **SMB Share** or **SFTP Upload** (WebDAV too, when run as a server collection) |
| **Output format** | JSON, or CSV and JSON |
| **Compression Level** | 0 to 9 (5 by default) |
| **Concurrency** | How many artifacts run at once (2) |
| **CPU Limit Percent** | Keep below this share of CPU (0 for no limit) |
| **Max Execution Time in Seconds** | Stop the whole collection after this long (0 for no limit) |
| Progress timeout | Stop if nothing new arrives for this long (1800 seconds) |
| **Pause For Prompt** | Wait for a key press before exiting, so a double-clicked window stays open |
| **Filename Format** | `Collection-%Hostname%-%TIMESTAMP%` by default |
| **Output Directory** / **Temp directory** | Where the zip and temporary files go (blank for the current folder and the system temp folder) |
| **Delete Collection at Exit** | Remove the local zip after a successful upload |

### Encryption

- **X509** (recommended): the results are encrypted with a random key,
  which is itself encrypted with a certificate. By default this is your
  server's certificate, so only your server (or someone with its
  configuration) can decrypt the results, and importing works directly.
  Anyone who intercepts the file sees nothing.
- **Password**: the zip is protected with a password you choose. Simpler
  to open by hand, but the password is inside the collector, so anyone who
  has the collector can open its output.
- **None**: a plain zip. Only for test data.

### Upload targets

When the machine can reach the internet (or your network), the collector
can send results straight to storage instead of leaving the zip on disk:

| Target | You provide |
|---|---|
| **S3 Bucket** | Bucket, region, credentials key and secret (and token), optional endpoint for S3-compatible storage, server-side encryption or KMS key |
| **Google Cloud Bucket** | Bucket and a service account key (JSON) |
| **Azure SAS URL** | A SAS URL for a container, from the Azure portal, with write permission |
| **SMB Share** | Share address (`\\192.168.1.1:445\Sharename`), user name and password |
| **SFTP Upload** | Server address, user, private key, upload path and optionally the host key |

Give each collector credentials that can **only write** (for example a
bucket policy that allows `PutObject` and nothing else), since the
credentials are inside the collector.

## With the command line

The `collector` command builds a collector from a spec file, on the server
or any machine with the server's configuration:

```bash
atlantiraptor --config server.config.yaml collector spec.yaml
```

A spec file:

```yaml
OS: Windows
Artifacts:
  Windows.Sysinternals.Autoruns:
    All: Y
  Generic.Client.Info: {}
Target: ZIP
EncryptionScheme: X509
OptPrompt: N
OptLevel: 5
OptConcurrency: 2
OptFilenameTemplate: "Collection-%FQDN%-%TIMESTAMP%"
OptFormat: jsonl
OptOutputDirectory: ""
OptCpuLimit: 0
OptProgressTimeout: 1800
OptTimeout: 0
```

`docs/offline_collector/sample.spec.yaml` in the
[repository](https://github.com/atlantsecurity/atlantiraptor) lists every
option.

## Tools inside the collector

Artifacts that need external tools (for example Autoruns or YARA rules
files) get those tools packed into the collector, so it runs without
network access. The server downloads them when you build the collector; see
[Tools](/artifacts/tools/).
