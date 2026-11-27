---
title: Managing artifacts
description: Create, customize, import, hide and delete Atlantiraptor artifacts, and keep custom artifacts in version control.
---

## Creating and editing

On **Artifacts**:

- **New** opens the editor with a template.
- **Customize** on a built-in artifact copies it to `Custom.<name>` and
  opens the copy. The built-in stays unchanged, and server upgrades keep
  updating it; your copy is yours to maintain.
- **Edit** and **Delete** work on custom artifacts.

**Check and save** validates the YAML and the VQL and stores the artifact.
It is available to collections and hunts at once. Collections already
running keep the version they started with.

Editing client artifacts needs `ARTIFACT_WRITER` (role
`artifact_writer`), and server artifacts `SERVER_ARTIFACT_WRITER`
(administrators). Both amount to running code on the machines where the
artifact runs, so keep them to a few people.

## Importing more artifacts {#importing-more-artifacts}

Run these server artifacts under **Server collections** (server
administrators):

| Artifact | Imports |
|---|---|
| `Server.Import.ArtifactBundle` | Every `.yaml` file in a zip at a URL, with a tag so you can find them later |
| `Server.Import.Extras` | Well-known external artifact collections in one go (Sigma rules, the Registry and SQLite hunters, triage artifacts and others; see the artifact's parameters for the list) |
| `Server.Import.PreviousReleases` | The built-in artifacts of an older release, renamed with a version prefix, for clients that can't be upgraded yet |

Artifacts from outside Atlant Security are not reviewed by us. Some
download and run external programs on your endpoints. Read them before
collecting them, and see [Artifact security](/artifacts/security/).

From VQL, `artifact_set(definition=...)` adds or replaces one artifact,
which is how you can load artifacts from your own sources:

```sql
SELECT artifact_set(definition=read_file(filename=OSPath)) AS Artifact
FROM glob(globs="/srv/artifacts/*.yaml")
```

## Loading artifacts from a folder

Start the server with `--definitions /path/to/folder` and every artifact in
that folder is loaded at startup. This is the
simplest way to deploy custom artifacts from version control: keep them in
a Git repository, check them with `atlantiraptor artifacts verify` in CI,
and deploy the folder with the server.

## Hiding and marking artifacts

`artifact_set_metadata()` changes how an artifact is offered without
editing it:

```sql
-- Hide an artifact from the pickers
SELECT artifact_set_metadata(name="Windows.Forensics.Lnk", hidden=TRUE)
FROM scope()

-- Let users with COLLECT_BASIC collect it
SELECT artifact_set_metadata(name="Custom.Triage.Basic", basic=TRUE)
FROM scope()
```

## Deleting

**Delete** removes a custom artifact. Collections and hunts that used it
keep their results. Built-in artifacts can't be deleted; hide them instead.

## After a server upgrade

Built-in artifacts are updated with the server. Custom artifacts, and
customized copies, are not: compare your `Custom.` copies with the new
built-in versions after an upgrade and carry over fixes you want.
