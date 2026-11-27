---
title: Updating Atlantiraptor
description: Signed automatic server updates from GitHub releases, manual upgrades, and agent upgrades.
---

## Automatic server updates

Atlantiraptor servers on Windows keep themselves up to date. They check
the [GitHub releases](https://github.com/atlantsecurity/atlantiraptor/releases)
of Atlantiraptor, and when a newer signed release is available they install
it and restart. The settings and status are on **Admin > Server updates**.

### What is checked before an install

The server installs a release only if all of these hold:

1. The release comes from the `atlantsecurity/atlantiraptor` repository on
   GitHub. This is fixed in the program; nothing at run time (configuration,
   console, API) can point it elsewhere.
2. The download matches the SHA-256 listed in the release's `SHA256SUMS`
   file.
3. It carries an Authenticode signature from **Atlant Security EOOD**,
   issued by Microsoft's code signing CA and trusted by Windows, with
   revocation checks.
4. It starts and reports the version number of the release.

Only then is the new program swapped in. The previous program is kept
until the next start.

### Settings

| Setting | Default | Notes |
|---|---|---|
| Install updates automatically | On | Off: the page still shows when an update is available, and an administrator installs it with one click. |
| Check GitHub every | 7 days (168 hours) | Between 1 hour and 30 days. **Check now** checks at once. |

Every install and every settings change is written to the
[audit log](/deployment/logging/#the-audit-log). Setting the environment
variable `ATLANTIRAPTOR_DISABLE_AUTO_UPDATE=1` on the server turns automatic
installs off regardless of the setting (for example during a change
freeze).

### Development builds

A binary built from source without a release version is a *development
build*. It never installs updates automatically. To move a development
build onto the release track, install a release once from **Admin > Server
updates**.

### Other platforms

Installing updates is supported on Windows servers. On Linux and in
containers the page shows when an update is available; upgrade as
described below.

### Making the server reach GitHub

The server needs outbound HTTPS to `api.github.com`, `github.com` and
`*.githubusercontent.com` (downloads are redirected there); the updater
refuses any other host. It uses the proxy from the server process's
environment (`HTTPS_PROXY`), if one is set.

## Manual server upgrades

1. Read the release notes.
2. [Back up](/deployment/backups/) the configuration and datastore.
3. Install the new program:
   - **Windows service**: stop the service, replace the program in the
     install folder, start the service. Or run
     `Atlantiraptor.exe --config server.config.yaml server_service install`
     with the new program, which does the same.
   - **Linux package**: build a new package from the new binary and install
     it over the old one (`dpkg -i` or `rpm -U`).
   - **Docker**: rebuild the image and recreate the container.
4. Check that the console loads and agents reconnect (the dashboard's
   connected clients count recovers within a few minutes).

The new server reads the existing configuration and datastore. Keep the
backup until you are satisfied with the new version: going back to an
older version after a newer one has written to the datastore is not
tested.

## Upgrading agents

The server and agents do not need the same version: newer servers work with
older agents. Upgrade agents to get new artifact capabilities and fixes.

- **Windows**: deploy the new MSI with Intune, Group Policy or your
  software deployment tool. It upgrades in place and keeps the client ID.
- **From the console**: **Fleet health** lists agents behind the newest
  version in your fleet, and can upgrade a selection by running
  `Admin.Client.Upgrade.Windows` or `Admin.Client.Upgrade.Debian` with the
  package you uploaded as that artifact's tool. See
  [Fleet health](/console/fleet-health/).
- **Linux**: install the new package with your configuration management.

Stage agent upgrades: a pilot label first, then everyone.

## Built-in artifacts after an upgrade

Built-in artifacts come with the program, so an upgrade brings updated
artifacts. Your custom artifacts are kept. If a built-in artifact you rely
on was renamed or removed, the server logs it; copy the old version into a
custom artifact if you still need it (see `Server.Import.PreviousReleases`).
