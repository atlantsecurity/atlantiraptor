---
title: Permissions
description: The permissions behind Atlantiraptor roles, what each one allows, and how to limit what VQL can do on the server and endpoints.
---

Roles are bundles of **permissions**. The server checks permissions on
every API call and inside every VQL query, so a user can't do in a notebook
or an artifact what their roles don't allow.

## The permissions

| Permission | Allows |
|---|---|
| `READ_RESULTS` | Read clients, collections, hunts, notebooks and their results |
| `ANY_QUERY` | Run VQL over data already on the server (notebooks, the API) |
| `LABEL_CLIENT` | Add and remove client labels and metadata |
| `COLLECT_CLIENT` | Start collections on clients |
| `COLLECT_BASIC` | Start collections of artifacts an administrator marked as basic (with `artifact_set_metadata(basic=TRUE)`) |
| `START_HUNT` | Create and start hunts |
| `COLLECT_SERVER` | Run server artifacts |
| `NOTEBOOK_EDITOR` | Create and edit notebooks and run their cells |
| `PREPARE_RESULTS` | Build export zips |
| `DELETE_RESULTS` | Delete collections, hunts and monitoring data |
| `ARTIFACT_WRITER` | Create and edit client artifacts |
| `SERVER_ARTIFACT_WRITER` | Create and edit server artifacts |
| `EXECVE` | Run programs (on endpoints, or on the server from server VQL) |
| `FILESYSTEM_READ` | Read files on the server from VQL |
| `FILESYSTEM_WRITE` | Write or delete files (on endpoints for response actions, and on the server) |
| `NETWORK` | Make network connections from VQL (HTTP requests, uploads) |
| `MACHINE_STATE` | Change machine state, such as killing processes or changing settings |
| `IMPERSONATION` | Run an artifact as another user (artifacts that declare `impersonate`) |
| `DATASTORE_ACCESS` | Read and write the server's datastore directly from VQL |
| `SERVER_ADMIN` | Server administration: users, settings, secrets, server monitoring |
| `ORG_ADMIN` | Create and manage organizations |

## What each role grants

| Role | Permissions |
|---|---|
| `reader` | `READ_RESULTS` |
| `analyst` | `READ_RESULTS`, `ANY_QUERY`, `NOTEBOOK_EDITOR`, `LABEL_CLIENT`, `PREPARE_RESULTS` |
| `investigator` | Analyst, plus `COLLECT_CLIENT`, `START_HUNT` |
| `hunter` | `READ_RESULTS`, `NOTEBOOK_EDITOR`, `LABEL_CLIENT`, `PREPARE_RESULTS`, `COLLECT_CLIENT`, `START_HUNT` |
| `responder` | Hunter, plus `EXECVE`, `FILESYSTEM_WRITE`, `NETWORK` |
| `artifact_writer` | `ARTIFACT_WRITER` |
| `org_admin` | `ORG_ADMIN` |
| `administrator` | Everything except `ANY_QUERY` and `DATASTORE_ACCESS` (in the root org, also `ORG_ADMIN`) |
| `api` | `ANY_QUERY`, `READ_RESULTS` |

## Artifacts can require permissions

An artifact can declare the permissions needed to collect it:

```yaml
name: Windows.Remediation.Quarantine
required_permissions:
  - EXECVE
  - NETWORK
```

The server checks these when the collection or hunt is started. A
`hunter` can therefore collect every read-only artifact, but the server
refuses response artifacts such as quarantine, which need `EXECVE`,
`FILESYSTEM_WRITE` or `NETWORK`. See [Artifact security](/artifacts/security/).

## Limiting file and network access from VQL

VQL that runs on the server (notebooks, server artifacts, the API) can
read files and reach the network, within the user's permissions. The
`security` section of the server configuration narrows that further for
everyone:

```yaml
security:
  # Paths the "file" accessor may read on the server (empty means all)
  allowed_file_accessor_prefix:
    - /srv/evidence/
  # Always refused, even if allowed above
  denied_file_accessor_prefix:
    - /etc/

  # Only these plugins, functions and accessors may be used (empty means all)
  allowed_plugins: []
  allowed_functions: []
  allowed_accessors: []

  # Or refuse specific ones
  denied_plugins:
    - execve
  denied_functions:
    - rm
  denied_accessors:
    - s3
```

To make clients refuse to run programs at all, set
`Client.prevent_execve: true` before building the client packages. This
also disables artifacts that rely on external tools.

### Lockdown

Set `lockdown: true` in the server configuration and restart, and the
server refuses the most dangerous permissions to **everyone**, including
administrators: `ARTIFACT_WRITER`, `SERVER_ARTIFACT_WRITER`, `EXECVE`,
`SERVER_ADMIN`, `FILESYSTEM_WRITE`, `FILESYSTEM_READ` and `MACHINE_STATE`
(change the list with `security.lockdown_denied_permissions`). Use it on a
server that should only collect and show results: if an administrator
account is stolen, the attacker can't use it to run code on the endpoints.
Turning lockdown off needs access to the server's configuration file.

## Checking permissions

- A user's page shows their **Effective permissions** in each org.
- Denied actions are refused with "permission denied" and are written to
  the server log.
- In VQL, `whoami()` returns the current user and `user()` a user's roles
  and permissions.
