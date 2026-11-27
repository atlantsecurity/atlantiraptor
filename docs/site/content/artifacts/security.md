---
title: Artifact security
description: How Atlantiraptor controls what artifacts may do - required and implied permissions, impersonation, and reviewing artifacts before you run them.
---

An artifact is code that runs as SYSTEM or root on every machine it is
collected from, or with server privileges on the server. Treat writing and
importing artifacts with the same care as deploying software.

## Who can write artifacts

| Action | Needs |
|---|---|
| Create or edit client artifacts | `ARTIFACT_WRITER` (role `artifact_writer`, administrators) |
| Create or edit server artifacts | `SERVER_ARTIFACT_WRITER` (administrators) |
| Import artifact packs | `SERVER_ADMIN` (the import artifacts require it) |

Someone who can write client artifacts and collect them can run any
command on your endpoints. Keep these permissions to a few people, and
review changes to custom artifacts.

## required_permissions

```yaml
required_permissions:
  - EXECVE
```

The server refuses to start a collection or hunt of the artifact unless the
user has every listed permission. Response artifacts (kill a process,
delete a file, quarantine) list `EXECVE`, `FILESYSTEM_WRITE` or `NETWORK`,
which is what keeps `hunter` users read-only. Declare them in your own
artifacts that change machines.

## implied_permissions

```yaml
implied_permissions:
  - NETWORK
```

The artifact verifier (run by **Check and save** and
`atlantiraptor artifacts verify`) warns when a client artifact uses a VQL
feature that needs a permission the artifact doesn't declare. List a
permission here to tell the verifier that its use is deliberate and safely
controlled by the artifact. It grants nothing at run time.

## impersonate

```yaml
impersonate: admin
```

The whole artifact runs with the permissions of the named user, not the
caller's. Combined with marking the artifact as basic, this lets you offer
one privileged operation (say, "start the standard triage hunt") to users
with only `COLLECT_BASIC`. See `Server.Utils.StartHuntExample` for a worked
example. An artifact can only be saved with `impersonate` set to the user
saving it, so an administrator has to save such an artifact themselves.

## Before you run an artifact from elsewhere

Artifacts from the internet, from other teams or from packs you import may
do more than they say. Before collecting one:

- read its sources; look for `execve()`, `http_client()`, `upload()`,
  `rm()`, registry writes and any `tools`,
- check where tools are downloaded from and pin their `expected_hash`,
- run it on one test machine and read the collection's **Log**,
- import packs with a tag so you can find, review and remove them later.

## Hardening the server

- `lockdown: true` refuses artifact writing and other dangerous
  permissions to everyone, even administrators. See
  [Lockdown](/users/permissions/#lockdown).
- `security.denied_plugins` and `denied_functions` can remove VQL features
  you never use, such as `execve`. See
  [Limiting file and network access from VQL](/users/permissions/#limiting-file-and-network-access-from-vql).
- `Client.prevent_execve` stops clients from running any program.
- The audit log records every artifact change and who made it. See
  [The audit log](/deployment/logging/#the-audit-log).
