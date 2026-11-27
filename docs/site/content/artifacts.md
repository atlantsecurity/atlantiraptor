---
title: Artifacts
description: What Atlantiraptor artifacts are, the kinds of artifacts, and how they package VQL queries for collection, hunting and monitoring.
---

Everything Atlantiraptor collects is collected by an **artifact**: a YAML
file that wraps one or more [VQL](/vql/) queries with a name, a
description, parameters and the permissions it needs. Users pick
artifacts and set parameters; they don't need to write VQL.

```yaml
name: Custom.Windows.RecentExecutables
description: |
  Executables in user Downloads folders, with their hash.
parameters:
  - name: Glob
    default: C:/Users/*/Downloads/*.exe
sources:
  - precondition: SELECT OS FROM info() WHERE OS = 'windows'
    query: |
      SELECT OSPath, Size, Mtime, hash(path=OSPath).SHA256 AS SHA256
      FROM glob(globs=Glob)
```

## Kinds of artifacts

The `type` field says where and how an artifact runs:

| Type | Runs | Used by |
|---|---|---|
| `CLIENT` (default) | Once, on a client | Collections, hunts, quick triage |
| `CLIENT_EVENT` | Continuously, on clients | [Client monitoring](/clients/monitoring/) |
| `SERVER` | Once, on the server | Server collections, cloud hunts, automation |
| `SERVER_EVENT` | Continuously, on the server | [Server events](/clients/monitoring/#server-events): alerting, forwarding, automation |
| `NOTEBOOK` | In a notebook | Notebook templates (the **Notebook** tab on the Artifacts page) |

## Built-in and custom artifacts

Atlantiraptor ships with about 500 built-in artifacts covering Windows,
Linux and macOS forensics, detection (Sigma, YARA), response actions,
cloud tenants and server automation. They are part of the server binary
and are updated with it. Browse them all in the
[artifact reference](/reference/artifacts/), or on the **Artifacts** page
in the console.

**Custom** artifacts are the ones you write or import. They are stored in
the server's datastore. Artifacts saved from the console must be named
`Custom.…` (the server adds the prefix if it is missing). To
change a built-in artifact, **Customize** it: this copies it to
`Custom.<name>` for you to edit, and the original stays as it is.

## Naming

Names are dotted: `<OS or area>.<category>.<what>`, such as
`Windows.EventLogs.RDPAuth` or `Linux.Sys.Users`. The first part is
`Windows`, `Linux`, `MacOS`, `Generic` (any OS), `Server`, `Cloud`, `Admin`
or `System`. The console's filters and the OS facets use these prefixes.

## The Artifacts page

**Artifacts** lists every artifact. Filter by type (**All**, **Client**,
**Server**, **Events**, **Notebook**), by **Built-in** or **Custom only**,
and search names and descriptions (press `/`). An artifact's page shows its
description, parameters, sources (the VQL), tools and references, and
offers:

- **Collect…** (from the selected client, or pick one) and **Hunt**,
- **Customize** (built-in) or **Edit** and **Delete** (custom),
- **New** to write an artifact from a template.

## In this section

- [Writing artifacts](/artifacts/writing/): the fields of an artifact,
  sources, preconditions, resources, exports and imports.
- [Parameters](/artifacts/parameters/): parameter types and how they reach
  the query.
- [Managing artifacts](/artifacts/managing/): editing, importing packs,
  deleting, and keeping custom artifacts in version control.
- [Tools](/artifacts/tools/): external programs and files that artifacts
  use.
- [Event artifacts](/artifacts/events/): writing monitoring artifacts.
- [Artifact security](/artifacts/security/): permissions, impersonation
  and reviewing artifacts from elsewhere.
- [Tips](/artifacts/tips/): patterns that make artifacts fast and robust.
