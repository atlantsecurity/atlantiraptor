---
title: Agent problems
description: Fix Atlantiraptor agents that don't connect, show as offline, share an identity, or use too many resources.
---

## A new agent doesn't appear

1. **Is it running?** On Windows `Get-Service Atlantiraptor`; on Linux
   `systemctl status velociraptor_client`; on macOS
   `launchctl list | grep -i velociraptor`.
2. **Run it in a terminal** to see what it does. Stop the service first,
   then, as administrator or root:

   ```bash
   atlantiraptor --config client.config.yaml client -v
   ```

   On Windows use the installed program and configuration in
   `C:\Program Files\Atlant Security\Atlantiraptor\`.
3. **Read the messages**:

   | Message | Cause and fix |
   |---|---|
   | connection refused, timeout | The endpoint can't reach the server. Check `Client.server_urls`, DNS, firewalls and that the frontend listens on that address and port |
   | certificate errors, `x509: …` | The name in `server_urls` doesn't match the server's certificate, a TLS-inspecting proxy is in the way, or a clock is wrong. See [TLS](/deployment/tls/) |
   | `407 Proxy Authentication Required` | The proxy needs authentication; allow the server's address without it, or set `Client.proxy`. See [Agents behind a proxy](/deployment/clients/#agents-behind-a-proxy) |
   | enrolment messages repeating | The server isn't accepting the client; check the server's frontend log |

4. **Check the configuration**: the client configuration must come from
   *this* server (`atlantiraptor --config server.config.yaml config client`).
   A configuration from another server, or an old one after
   [rotating keys](/deployment/tls/#renewing-the-internal-certificates),
   won't connect.

## A host shows as offline

The dashboard counts a host as connected when it was seen in the last 15
minutes. If a running agent shows as offline:

- the machine is asleep, or off the network (laptops),
- a network change (VPN, proxy) blocks it; run it with `-v` as above,
- the server is overloaded and slow to answer; see
  [Server problems](/troubleshooting/server/).

Collections and hunts wait for offline hosts: they run when the host
connects again (until the hunt expires).

## Two machines share one identity

A client's identity is in its writeback file. If a disk image or VM
template contained one, every clone has the same client ID, and the host
page flips between machines.

`Server.Monitor.ClientConflict` (a server event artifact) detects this and
makes the affected clients create new identities. To prevent it, install
the agent on golden images without starting it, or delete the writeback
file before sealing the image. See
[Cloned machines and VDI](/deployment/clients/#cloned-machines-and-vdi).

## An agent uses too much CPU or memory

1. Look at what it is doing: the host's **Collections** (running ones) and
   the monitoring artifacts it runs (**Client events**).
2. Collect `Generic.Client.Stats` as monitoring to watch its CPU and
   memory over time.
3. Usual causes:
   - a heavy collection (hashing or YARA over a whole disk, the MFT): set a
     CPU limit when starting it, see
     [Load on endpoints](/deployment/performance/#load-on-endpoints),
   - an event artifact that sends too many events (an unfiltered ETW
     provider, a busy log): filter it on the client, or target it with a
     label,
   - antivirus scanning the agent's temporary files: exclude the agent's
     folder.
4. For a bug report, collect `Generic.Client.Profile` while the problem is
   happening (see [Debugging](/troubleshooting/debugging/)).

## An agent stopped after an upgrade

Upgrade agents with the [fleet upgrade](/console/fleet-health/) or a new
MSI. If an agent doesn't come back, run it in a terminal as above. The
writeback file keeps the client's identity across upgrades.

## Removing an agent completely

See [Removing agents](/deployment/clients/#removing-agents). Delete the
client on the server too if you won't reinstall it.
