---
title: Security
description: How Atlantiraptor protects its server, its agents and the evidence it collects, how to harden a deployment, and how to report a vulnerability.
---

An incident response platform holds the keys to every endpoint and the
evidence of every incident. This page summarises how Atlantiraptor
protects them, and what you should do to keep your deployment safe.

## Reporting a vulnerability

Please report security problems in Atlantiraptor privately, not in a
public issue. Use **Report a vulnerability** on the
[repository's Security tab](https://github.com/atlantsecurity/atlantiraptor/security),
or contact [Atlant Security](https://atlantsecurity.com). Include the
version (`atlantiraptor version`), what you found and how to reproduce it.
We'll confirm receipt, keep you informed, and credit you when the fix is
released, if you wish.

Vulnerabilities in code inherited from Velociraptor may also affect the
upstream project; we coordinate with its maintainers where that applies.

Fixed vulnerabilities are listed on [Security advisories](/security/advisories/).

## How Atlantiraptor protects itself

### Agents and the server

- Agents talk to the server over TLS, and their messages are additionally
  encrypted and signed with keys from the deployment's own CA. Each client
  has its own key; the server's certificate is pinned in the client
  configuration, so an agent can't be redirected to another server.
- Agents only run what the server sends them, and only the server (with a
  user's permissions behind it) can schedule work.
- See [TLS and certificates](/deployment/tls/).

### The console and APIs

- Users sign in with a password and two-factor authentication, or single
  sign-on; two-factor sign in is required for everyone by default. See
  [Authentication](/deployment/authentication/).
- Every action is checked against the user's roles in that organization.
  See [Users and roles](/users/) and [Permissions](/users/permissions/).
- The console and the API can be limited to allowed networks. See
  [Network access](/deployment/network-access/).
- REST API keys are scoped by role, address and expiry, rate limited and
  audited. See [API keys](/server-automation/api-keys/).

### Code that runs on endpoints

- Response actions need specific permissions, can need a second
  approver, and run as dry runs first where possible. See
  [Response actions](/console/response/).
- Artifacts declare the permissions they need; the server refuses them to
  users without. See [Artifact security](/artifacts/security/).

### Updates and content

- Release binaries are Authenticode-signed by Atlant Security EOOD. A
  server installs an update only after checking its SHA-256 checksum and
  its signature. See [Updating](/deployment/updates/).
- Premium hunt feed content is signed by Atlant Security and verified
  with keys built into the release. See [Hunt feeds](/hunts/feeds/).

### Stored data

- Credentials for integrations and cloud tenants are kept as
  [secrets](/secrets/), encrypted in the datastore and never shown to
  queries.
- Evidence exports can be password protected or encrypted to the server's
  certificate. See [Exporting evidence](/evidence/).
- The [audit log](/deployment/logging/#the-audit-log) records sign ins,
  permission changes, collections, response actions and configuration
  changes.

## Hardening checklist

1. Keep the server up to date; turn on automatic updates on Windows.
2. Put the console and the API behind network allowlists, or a VPN, and
   expose only the client frontend port (8000) to the internet.
3. Require two-factor sign in (the default) or use SSO with your identity
   provider's MFA.
4. Give people the least role that works. Keep `administrator`,
   `artifact_writer` and `responder` to a few named people.
5. Turn on two-person approval for response actions.
6. Use secrets for every credential, and `security.vql_must_use_secrets`
   to enforce it.
7. Protect the server's configuration file and datastore: whoever has the
   configuration has the CA key, and can impersonate the server.
8. Back up the configuration and the datastore, and test restoring. See
   [Backups](/deployment/backups/).
9. Forward the audit log to your SIEM.
10. Consider [lockdown](/users/permissions/#lockdown) for servers that
    should only collect.
