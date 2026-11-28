---
title: Organizations
description: Run several isolated tenants on one Atlantiraptor server - for customers, subsidiaries or business units.
---

An **organization** (org) is an isolated tenant on one server. Each org has
its own agents, labels, hunts, collections, notebooks, cases, custom
artifacts, client monitoring and server monitoring, and users have roles
per org. A managed service provider can serve many customers from one
server, and a company can separate subsidiaries that must not see each
other's data.

Every server has a **root org** (ID `root`), created at install. Server-wide
settings (updates, network access, the two-factor policy, the hunt feed
licence) live there.

## Creating an org

Creating orgs needs the `ORG_ADMIN` permission, which administrators of the
root org have. In the root org:

1. Open **Server collections** and click **Collect**.
2. Choose `Server.Orgs.NewOrg`, set **OrgName** (for example `Acme Ltd`)
   and collect it.

The artifact creates the org, assigns it an ID such as `O1a2b3`, makes you
its administrator, and runs `Server.Utils.CreateMSI` and
`Server.Utils.CreateLinuxPackages` inside it, which build agent packages
with the new org's configuration. Add more initial artifacts with the
**InitialArtifacts** parameter if you want, for example client monitoring
or custom artifacts every customer needs.

The same with VQL, in a notebook:

```sql
SELECT org_create(name="Acme Ltd") FROM scope()
```

`Server.Orgs.ListOrgs` (or `SELECT * FROM orgs()`) lists all orgs.

## Agents for an org

Each org has its own client configuration, which carries the org's ID.
Agents built with it enroll into that org. The packages that
`Server.Orgs.NewOrg` builds are in that collection's uploaded files, in the
new org. To build them again, switch to the org and collect
`Server.Utils.CreateMSI` or `Server.Utils.CreateLinuxPackages`, or get the
org's client configuration and build packages as described in
[Deploying agents](/deployment/clients/).

All orgs share the server address and CA; an agent cannot move to another
org without being reinstalled with that org's configuration.

## Users in several orgs

A user account is server-wide; roles are per org. An analyst at a managed
service provider can be `hunter` in five customer orgs and `reader` in
another. Give access on **Server settings > Users**: select the user, **Add to org**,
and pick roles. The org switcher in the account menu (**Switch
organization**) lists the orgs a user has access to. Console URLs carry the
org (`?org_id=O1a2b3`), so a shared link opens in the right org.

Roles mapped from single sign-on apply to every org; for per-org access,
give roles in the console.

## Hunting across orgs

A hunt normally runs in the current org. In **New hunt**, **Also run in
these organizations** starts the same hunt in other orgs where you may
hunt. Each org's results stay in that org.

## Artifacts in orgs

Built-in artifacts are available in every org. Custom artifacts belong to
the org they were created in. To add the same custom artifact to several
orgs, create it in each, or use `artifact_set()` with `org_id` from the root
org. See [Managing artifacts](/artifacts/managing/).

## Deleting an org

Deleting an org removes its data permanently. From a notebook in the root
org, first see what would be removed, then confirm:

```sql
SELECT org_delete(org="O1a2b3") FROM scope()
SELECT org_delete(org="O1a2b3", really_do_it=TRUE) FROM scope()
```

Uninstall the org's agents first, or they will keep trying to connect.

## Moving an org to another server

An org's data lives in its own folder of the datastore. To move it, the
new server must have the same CA (so the agents trust it) and the same
address, or the agents must be redeployed. See
[Backups and disaster recovery](/deployment/backups/).
