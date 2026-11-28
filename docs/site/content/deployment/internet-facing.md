---
title: Internet-facing agents
description: Let laptops connect from anywhere by exposing only the agent port, with mutual TLS so that only your own agents get past the handshake, and block lost computers in one click.
---

Agents on laptops and remote sites need to reach the server from
anywhere. You can do that safely by exposing **one port, the agent port**
(the frontend, 8000 by default), and keeping everything else private.
With **agent certificates** (mutual TLS) turned on, every connection to
that port has to present a certificate this server trusts during the TLS
handshake. Scanners, bots and attackers are dropped before any server
code reads what they send.

## What protects the agent port

Three layers, each one independent of the others:

1. **The agent checks the server.** Agents accept only a server whose
   certificate your server's own CA signed (or the pinned certificate), so
   nobody can impersonate your server, even with a valid public
   certificate.
2. **The server checks the agent (mutual TLS).** Each agent presents a
   certificate for its own key, the key its client ID is derived from.
   The server accepts it only if that key is one it enrolled and has not
   blocked, or, for a brand new agent, if the certificate is signed by
   the deployment certificate from your installers. Everyone else fails
   the TLS handshake.
3. **Messages are encrypted end to end** with the agent's and the
   server's keys, inside the TLS connection, as they always were. A proxy
   that breaks TLS still sees nothing.

## Ports

| Port | Default | Who needs it | Expose to the internet? |
|---|---|---|---|
| Agent port (frontend) | 8000 | Agents | Yes, this is the only one |
| Console | 8889, `127.0.0.1` | Analysts' browsers | No: VPN, SSH tunnel, or a reverse proxy with sign-in |
| gRPC API | 8001, `127.0.0.1` | `api_client` tools | No |
| Monitoring | 8003, `127.0.0.1` | Prometheus | No |

New servers already listen on the console, API and monitoring ports on
`127.0.0.1` only. Check `GUI.bind_address` in the server configuration: if
it is `0.0.0.0`, the console is reachable from the network. To reach a
console that listens on `127.0.0.1` from your desk, use a VPN, an SSH
tunnel (`ssh -L 8889:127.0.0.1:8889 server`), Remote Desktop to the
server, or [your own address](/deployment/tls/#your-own-address-from-the-console)
with [Network access](/deployment/network-access/) limits and
[two-factor sign in](/deployment/authentication/#two-factor-sign-in).

Agent certificates need the agent port on its own port. If the console
shares the agent port (`GUI.bind_port` equals `Frontend.bind_port`),
browsers would be asked for certificates, so the check stays off and the
page says so.

On the firewall (Windows Defender Firewall, your router, or the cloud
security group), allow inbound TCP to the agent port from anywhere and
nothing else:

```powershell
New-NetFirewallRule -DisplayName "Atlantiraptor agents" -Direction Inbound `
  -Protocol TCP -LocalPort 8000 -Action Allow -Profile Any
```

## Turning on agent certificates

Open **Server settings > Agent connections**. The check has three modes:

- **Off**: the agent port asks for no certificate. Anyone can connect;
  the server still refuses messages that are not encrypted with an
  enrolled agent's key.
- **Warn** (the default): agents are asked for their certificate and
  everyone still gets in. The page counts what each agent seen in the last
  24 hours presents and lists the ones that would be refused.
- **Enforce**: connections without an acceptable certificate fail the
  TLS handshake.

Changing the mode takes effect for new connections at once, with no
restart.

### Migrating existing agents

1. Leave the mode on **Warn**, or choose it.
2. Update the server to 1.0.8 or later. [Agent upgrades](/deployment/updates/#automatic-agent-upgrades-windows)
   bring Windows agents to the same version, and from then on they present
   their own certificate. Agents that already enrolled need nothing else:
   the server recognizes them by the key they enrolled with.
3. Watch **Agents without their own certificate** shrink. Linux and macOS
   agents are not upgraded automatically; reinstall them with the commands
   under [Deploy a client](/deployment/clients/).
4. When the page says every agent would get in, choose **Enforce**. If
   agents seen in the last 24 hours would still be refused, the page tells
   you how many and asks before it turns Enforce on.

Older agents whose client configuration came from the configuration
wizard carry a shared deployment certificate and present it as is. While
**Accept older agents** is on, Enforce lets them in (they still keep
scanners out, but can't be blocked in the handshake). Turn it off once
every agent has upgraded.

## New installs: GPO, Intune and MSI

Nothing changes in how you deploy. Every client configuration the server
hands out, from **Server settings > Deploy a client** (the MSI
configuration, the Intune package and the install scripts) and from
`Atlantiraptor.exe config client`, contains the server's **deployment
certificate**. On its first start, a new agent signs a certificate for its
own key with it and presents both. The server accepts that while **New
agents can enroll** is on, the agent enrolls, and from its next connection
on it is recognized by its own key. Thousands of computers can install at
once with no manual step.

Client configurations made before 1.0.8 may not contain a deployment
certificate. Agents installed from them enroll fine in Warn mode, and keep
working in Enforce mode once enrolled, but a new computer can't enroll
while Enforce is on. Download the configuration or Intune package again
from Deploy a client before turning on Enforce if you keep installing new
computers with an old package.

### Pausing enrollment and rotating the deployment certificate

- **New agents can enroll** off: only agents that already enrolled can
  connect. Use it when you are not deploying, or right after a laptop is
  stolen, so a thief can't reinstall the agent as a new computer.
- **Rotate…** issues a new deployment certificate. Enrolled agents keep
  working. Installers and Intune packages made before the rotation stop
  enrolling new computers in Enforce mode, and older agents that present
  only the old deployment certificate are refused. Download new
  installers from Deploy a client afterwards.

Rotations, mode changes and blocks are in the [audit log](/deployment/audit-log/)
as `agent_mtls_settings`, `agent_mtls_rotate_deployment`, `agent_block`
and `agent_unblock`.

## Blocking a lost or stolen computer

Open the computer's page and choose **More actions > Block agent**. The
server:

- refuses the agent's messages from now on, in every mode,
- refuses its certificate in the TLS handshake (Warn and Enforce),
- closes its open connections.

The computer's data and history stay. Unblock it from the same menu or
from **Server settings > Agent connections > Blocked agents**.

Blocking needs the **server administrator** role. To make sure the same
computer can't come back as a new agent, also pause enrollment or rotate
the deployment certificate (see above).

## Troubleshooting

- **Recent refused or unrecognized connections** on the Agent connections
  page lists handshakes that failed or would fail, with the address and
  reason, at most once a minute per agent or address.
- *unknown agent key*: a computer whose agent was deleted from the
  console, or someone else's certificate. Reinstall the agent if it is
  yours.
- *new enrollments are paused*: turn on New agents can enroll.
- *unknown agent signed by an old or unknown deployment certificate*: the
  installer predates a rotation; download a new one.
- A load balancer health check on the agent port fails in Enforce mode,
  because it has no certificate. Check the console port instead, or use a
  TCP check.
- If agents are cut off by mistake, choose Warn on the page. Agents
  reconnect by themselves within minutes. If you can't reach the console,
  restart the server with the environment variable
  `ATLANTIRAPTOR_DISABLE_AGENT_MTLS=1`, which turns the check off until it
  is removed.
- Load balancers or proxies that terminate TLS in front of the agent port
  hide the agent's certificate from the server, so agent certificates
  can't be used behind them. Use TCP (layer 4) pass-through instead.
