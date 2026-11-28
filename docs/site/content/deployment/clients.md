---
title: Deploying agents
description: Install the Atlantiraptor agent on Windows, Linux and macOS endpoints, with the signed MSI, packages, or temporarily without installing.
---

An agent needs two things: the Atlantiraptor program and the **client
configuration** of your server (`client.config.yaml`), which tells it where
the server is and which CA to trust. Each agent creates its own key the
first time it starts and stores it in its *writeback file*; the server then
lists it as a new client.

The quickest way to get both is the console: **Clients > Deploy a
client** (server administrators only) shows the client configuration and a
ready-to-copy install command for Windows, Linux and macOS, install
scripts, and a [Microsoft Intune package](/deployment/intune/). Each
view and download is recorded in the audit log. The rest of this page
describes the same steps by hand.

Get the client configuration with:

```sh
atlantiraptor --config server.config.yaml config client > client.config.yaml
```

The configuration holds no private key, but its *nonce* is the org's
enrollment secret: anyone who has the file can enroll a computer to your
server. The nonce is created with the server (or org); it can't be changed
without re-deploying every agent.

## Windows

### The MSI installer (recommended)

The Atlantiraptor MSI installs the agent as the Windows service
**Atlantiraptor**, running as LocalSystem, under
`C:\Program Files\Atlant Security\Atlantiraptor\`. That folder holds the
program, the client configuration, the writeback file
(`atlantiraptor.writeback.yaml`) and a `Tools` folder for temporary files
and tools, and is readable only by SYSTEM and administrators. Uninstalling
removes the folder.

Atlant Security can build an MSI with your server's client configuration
inside, signed with its code signing certificate. To build one yourself on
Windows (PowerShell 7 and WiX v5 needed):

```powershell
dotnet tool install --global wix
wix extension add -g WixToolset.Util.wixext/5.0.2
pwsh -File scripts/build-msi.ps1 -Binary .\Atlantiraptor.exe `
     -ClientConfig .\client.config.yaml -Version 1.0.3
```

The script refuses an unsigned binary; `-AllowUnsigned` builds anyway for
testing. Sign the resulting MSI before you distribute it, because Windows
and endpoint protection tools treat unsigned installers with suspicion.
Keep the same version numbering as the program: installing a newer MSI
upgrades the agent in place.

Deploy the MSI like any other:

```powershell
msiexec /i Atlantiraptor-1.0.3-amd64.msi /qn
```

- **Intune**: add it as a *Line-of-business app* and assign it to a device
  group, or use the Win32 app package from the console (see
  [Deploying with Intune](/deployment/intune/)).
- **Group Policy**: assign it under *Computer Configuration > Policies >
  Software Settings > Software installation*.
- **SCCM / other tools**: use the silent command above.

### Without the MSI

The console's `Install-Atlantiraptor.ps1` (**Clients > Deploy a client >
Windows**) installs the agent the same way as the MSI, after checking the
program's signature. Run it as an administrator:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-Atlantiraptor.ps1
```

`-Uninstall` removes the agent again (also one installed by the MSI).

On a single machine, the program can also install itself as a service:

```powershell
.\Atlantiraptor.exe --config client.config.yaml service install
```

This copies the program and configuration to
`Client.windows_installer.install_path` and creates the service named by
`Client.windows_installer.service_name`. `service remove` uninstalls it.

### Checking an agent

```powershell
Get-Service Atlantiraptor
```

Within a minute the host appears on the dashboard under **Recently seen**,
and under **Clients**. If not, see [Agent problems](/troubleshooting/clients/).

## Linux

The **Linux** tab of **Clients > Deploy a client** gives a command (and
the script `install-atlantiraptor-linux.sh`) that installs the program
from the current folder as the systemd service `atlantiraptor`, under
`/opt/atlantiraptor`:

```sh
sudo sh install-atlantiraptor-linux.sh --binary ./atlantiraptor
```

Or build a package that contains the program, the client configuration and a
systemd unit, then install it with your usual tools (Ansible, Puppet, an
RMM, or by hand):

```sh
atlantiraptor --config client.config.yaml debian client --binary ./atlantiraptor
sudo dpkg -i velociraptor_client_*.deb

atlantiraptor --config client.config.yaml rpm client --binary ./atlantiraptor
sudo rpm -i velociraptor_client_*.rpm
```

The service is called `velociraptor_client`. The agent runs as root, so it
can read the whole system.

For systems without systemd, or for a quick test, run the agent in the
foreground:

```sh
sudo ./atlantiraptor --config client.config.yaml client -v
```

The agent binary is static and runs on most distributions. On very old
systems (for example with an old glibc), use a binary built with musl.

## macOS

The **macOS** tab of **Clients > Deploy a client** works like the Linux one
and installs the launchd daemon `com.atlantsecurity.atlantiraptor` under
`/usr/local/atlantiraptor`. Or let the program install itself:

```sh
sudo ./atlantiraptor --config client.config.yaml service install
```

This installs a launchd service (`com.velocidex.velociraptor` by default,
set by `Client.darwin_installer`). For full visibility, grant the program
**Full Disk Access** with an MDM profile (PPPC payload) before installing,
or in System Settings > Privacy & Security. Without it, the agent cannot
read protected locations such as Mail data or other users' folders.

## Labels at install time

To label agents from the moment they enroll (for example by site or
department), add labels to the client configuration before you build the
package:

```yaml
Client:
  labels:
    - site-london
    - workstations
```

Labels are also easy to add later, by hand or with
[automatic labeling](/clients/#labels).

## Agents behind a proxy

If endpoints reach the internet only through a proxy, set it in the client
configuration:

```yaml
Client:
  proxy_config:
    http: http://proxy.example.com:3128
    https: http://proxy.example.com:3128
```

Agents also follow the operating system's proxy environment variables
unless `ignore_environment` is set. A proxy that inspects TLS breaks
self-signed verification; exempt the Atlantiraptor server from inspection
or use a [public certificate](/deployment/tls/).

## Running without installing

During an incident you may want visibility on machines where you cannot
install anything permanently. Options:

- **Run the agent in the foreground** from a share or a USB drive:
  `Atlantiraptor.exe --config client.config.yaml client`. It connects
  while it runs and leaves no service behind. Use a writeback path on a
  temporary folder.
- **Push a temporary agent** with your remote management tool, or as a
  scheduled task that runs the command above, and remove it after the
  engagement.
- **Collect without an agent** with an [offline collector](/offline/).

A machine that runs the agent this way gets a new client ID each time its
writeback file is lost.

## Cloned machines and VDI

The client ID comes from the writeback file. If you build a golden image
with the agent installed and started, every clone shares the same ID, and
the server sees them as one machine flapping between hosts. Install the
agent on the image without starting it, or delete the writeback file before
sealing the image.

## Upgrading agents

- **With the MSI**: deploy the new MSI the same way; it upgrades in place.
- **From the console**: **Fleet health** shows agents running older
  versions and can upgrade them by running `Admin.Client.Upgrade.Windows`
  (or `.Debian`) with the package you uploaded for that artifact's tool.
  See [Fleet health](/console/fleet-health/).
- **As a hunt**: run the same upgrade artifacts as a hunt, targeted by
  label to stage the rollout.

Agents older than the server keep working; upgrade them in your own time.

## Removing agents

Uninstall the MSI or package, or use the response action **Uninstall
agent**. Then delete the client from the console (**Clients**, select,
**Delete**) to remove its data, or keep it for its history.
