---
title: Deploying Atlantiraptor
description: Plan an Atlantiraptor deployment - server placement, ports, certificates, sign in, storage and agent rollout.
---

A production deployment has one server (or a few, for very large fleets)
that every endpoint can reach, and an agent on each endpoint. This page
lists the decisions to make before you install anything. The pages that
follow walk through each step.

## The steps

1. **Decide where the server runs** and how endpoints reach it (below).
2. **Install the server** on Windows or Linux: [Installing the server](/deployment/server/),
   or in a container: [Docker](/deployment/docker/).
3. **Create the configuration** with the wizard and adjust it:
   [Server configuration](/deployment/configuration/).
4. **Set up certificates**: [TLS certificates](/deployment/tls/).
5. **Set up sign in** for analysts, with two-factor or single sign-on:
   [Authentication](/deployment/authentication/).
6. **Create users and give them roles**: [Users and roles](/users/).
7. **Deploy agents** to endpoints: [Deploying agents](/deployment/clients/).
8. **Restrict access** to the console: [Network access](/deployment/network-access/).
9. **Plan for updates, backups and retention**:
   [Updating](/deployment/updates/), [Backups](/deployment/backups/),
   [Storage and data retention](/deployment/storage/).

## Where the server runs

The server needs to be reachable by every endpoint, including laptops
outside the office, so it is usually one of:

- **A cloud virtual machine** with a public DNS name. This is the simplest
  way to reach remote laptops. Restrict the console port to your team's
  addresses (see [Network access](/deployment/network-access/)).
- **A server in your data center** reachable over VPN, or published
  through a firewall or reverse proxy.
- **A machine at the customer's site**, for a managed service or an
  incident response engagement.

Atlant Security publishes signed releases of the server for **Windows**
(x64), and Windows servers can [update themselves](/deployment/updates/).
The server can also run on **Linux**, built from source; Linux is a good
choice for very large fleets and for containers.

## Ports

| Port | Used by | Default | Notes |
|---|---|---|---|
| Frontend | agents | 8000 | Must be reachable from every endpoint. Often moved to 443. |
| Console and APIs | analysts, SIEM | 8889 | Keep this private: VPN, allowlist or reverse proxy with SSO. |
| gRPC API | scripts and other servers | 8001 | Only if you use the [gRPC API](/server-automation/grpc-api/). |
| Monitoring | Prometheus | 8003 | Optional metrics endpoint, bound to localhost by default. |

The frontend and the console can share a port, but keeping them separate
makes it easy to expose only the frontend to the internet.

## Names and certificates

Agents connect to the server by the URL in their configuration, for
example `https://atlantiraptor.example.com:8000/`. Choose a DNS name that
will not change: every agent has it in its configuration. You have three
choices for the certificate (see [TLS certificates](/deployment/tls/)):

- **Self-signed** (the default): the server's own certificate authority
  signs the certificate, and agents trust only that CA. This works with any
  name or an IP address and needs no outside service. Browsers warn about
  the console certificate unless you add the CA to them.
- **Let's Encrypt**: the server gets and renews a certificate by itself.
  Needs a public DNS name and port 80 open to the internet for the
  challenge.
- **Your own certificate** from your company CA or a commercial CA.

## Sign in

Users sign in with a username and password plus a code from an
authenticator app, or through single sign-on with Microsoft Entra ID,
Google, GitHub, Okta or any OpenID Connect provider. See
[Authentication](/deployment/authentication/).

## Size

A single server with 4 CPU cores, 8 GB of memory and a fast SSD handles
several thousand endpoints for typical use. What grows fastest is disk
space: hunts that collect files, and monitoring artifacts that run on every
endpoint, write a lot of data. Plan for 100 GB to start and monitor usage.
See [Performance and sizing](/deployment/performance/) and, for tens of
thousands of endpoints, [Scaling out](/deployment/scaling/).

## Multiple customers or business units

One server can hold several isolated [organizations](/deployment/orgs/),
each with its own agents, users and data. Use this for a managed service
instead of running a server per customer.

## A checklist before going live

- [ ] The server's DNS name resolves from endpoints and the frontend port
      is reachable.
- [ ] The configuration file is backed up somewhere safe. It contains the
      CA private key: without it, agents cannot talk to a rebuilt server.
- [ ] Every user has two-factor sign in or single sign-on.
- [ ] The console port is not open to the whole internet.
- [ ] Disk space is monitored and a [retention](/deployment/storage/#deleting-old-data)
      plan exists.
- [ ] Backups of the datastore are scheduled.
- [ ] Agents are deployed with the signed MSI or packages built from this
      server's configuration.
