---
title: Add more computers
description: Install the Atlantiraptor agent on more Windows, Linux and macOS computers, by hand or with Intune, Group Policy or another deployment tool.
---

Each computer needs the agent and your server's **client configuration**
(`client.config.yaml`), which tells the agent where the server is. You got
that file when you created the server's configuration (see
[Set up a test lab](/quickstart/#b-a-server-and-a-second-computer)).

## Windows: the installer

The easiest way is an **MSI installer** with your client configuration
inside. It installs the agent as the Windows service **Atlantiraptor** and
upgrades it in place when you install a newer version.

- **Ask Atlant Security** for an MSI built for your server and signed with
  its certificate, or
- build one yourself as described in
  [Deploying agents](/deployment/clients/#the-msi-installer-recommended).

Then install it on each computer:

- **By hand**: double-click the MSI, or run
  `msiexec /i Atlantiraptor-amd64.msi /qn` as an administrator.
- **Intune**: add it as a *Line-of-business app* and assign it to a device
  group.
- **Group Policy**: assign it under *Computer Configuration > Policies >
  Software Settings > Software installation*.
- **SCCM or another tool**: use the `msiexec` command above.

## Windows: without an installer

On a few computers, copy `Atlantiraptor.exe` and `client.config.yaml` to
the computer and run, as an administrator:

```powershell
.\Atlantiraptor.exe --config client.config.yaml service install
```

## Linux and macOS

The server can build a Debian or RPM package for Linux, and the agent can
install itself as a service on macOS. See
[Deploying agents](/deployment/clients/#linux).

## Check that it worked

Within a minute the new computer appears on the dashboard under **Recently
seen** and under **Clients**. If it doesn't, see
[Agent problems](/troubleshooting/clients/).

## Group your computers

Give computers **labels**, such as `servers`, `finance` or `laptops`, to
target hunts and responses at a group. Label rules can label new computers
automatically by name or operating system. See [Labels](/clients/#labels).
