---
title: Installing the server
description: Install the Atlantiraptor server on Windows or Linux and run it as a service.
---

The server is the same `Atlantiraptor.exe` program as the agent, started
with a server configuration file. This page installs it as a service on
Windows or Linux. Before you start, read [Deploying Atlantiraptor](/deployment/)
and choose the DNS name, ports and certificate type.

## Windows

On Windows the server always runs as a Windows service: it starts with
Windows, restarts if it stops, and [updates itself](/deployment/updates/)
by restarting the service. Do every step below in one PowerShell window
opened **as administrator** (right-click **Windows PowerShell** and choose
**Run as administrator**); installing a service needs it.

### 1. Prepare the machine

- Windows Server 2019 or later (x64), or Windows 10/11 for a small or lab
  deployment.
- A dedicated data folder on a fast disk, for example `D:\Atlantiraptor`.
- Firewall rules allowing the frontend (agent) port, 8000 by default,
  from endpoints. The console (8889) listens on the server itself only;
  reach it over a VPN, an SSH tunnel or Remote Desktop rather than
  opening it to the network. For laptops that connect from anywhere, see
  [Internet-facing agents](/deployment/internet-facing/).

### 2. Download and check the program

```powershell
New-Item -ItemType Directory -Force C:\AtlSetup | Out-Null
cd C:\AtlSetup
Invoke-WebRequest -UseBasicParsing -OutFile Atlantiraptor.exe `
  https://github.com/atlantsecurity/atlantiraptor/releases/latest/download/Atlantiraptor-windows-amd64.exe
Get-AuthenticodeSignature .\Atlantiraptor.exe | Format-List Status, SignerCertificate
```

The status must be `Valid` and the signer `Atlant Security EOOD`. If it
isn't, delete the file and don't run it.

### 3. Create the configuration

Run the interactive wizard and answer its questions (server operating
system, data folder, certificate type, public DNS name, ports, first
administrator):

```powershell
.\Atlantiraptor.exe config generate -i
```

It writes `server.config.yaml`, which contains the server's private keys. See
[Server configuration](/deployment/configuration/) for what the wizard
creates and how to change it later.

### 4. Check the service name

The service's name and folder come from `Client.windows_installer` in the
server configuration. The wizard sets them to:

```yaml
  windows_installer:
    service_name: AtlantiraptorServer
    install_path: $ProgramFiles\Atlantiraptor Server\AtlantiraptorServer.exe
    service_description: Atlantiraptor server by Atlant Security
```

Agents installed from **Server settings > Deploy a client**, the MSI, or a
client configuration made with `config client` always get their own
service, `Atlantiraptor`.

Configurations made by version 1.0.5 or earlier, and by the `gui` lab,
still say `Velociraptor` under `C:\Program Files\Velociraptor\`. For a new
server, change them before you install:

```powershell
(Get-Content .\server.config.yaml) `
  -replace 'service_name: Velociraptor$', 'service_name: AtlantiraptorServer' `
  -replace 'install_path: \$ProgramFiles\\Velociraptor\\Velociraptor\.exe$', 'install_path: $ProgramFiles\Atlantiraptor Server\AtlantiraptorServer.exe' `
  -replace 'service_description: Velociraptor service$', 'service_description: Atlantiraptor server by Atlant Security' |
  Set-Content .\server.config.yaml
```

A server that already runs as the `Velociraptor` service keeps that name;
don't change it there, or the next install creates a second service.

> **Warning:** Never use `Atlantiraptor` (the agent's service) or the name
> of any other service on the machine. The install replaces a service
> with the same name, and its program file, without asking.

### 5. Install and start the service

Before you install, check two things:

- **Nothing else is running this server.** A test copy started with
  `gui`, `frontend` or a scheduled task holds the same ports, and the
  service then can't start. This must print nothing:

  ```powershell
  Get-NetTCPConnection -State Listen -LocalPort 8000,8889 -ErrorAction SilentlyContinue
  ```

- **The log has a folder.** A service has no console window, so the server
  only writes log files when `Logging.output_directory` is set. The
  wizard sets it. A configuration made another way, for example one
  written by the `gui` lab into its data folder, may not have it. Then add
  it under `Logging:` (for example `output_directory: D:\Atlantiraptor\logs`)
  and create the folder.

```powershell
.\Atlantiraptor.exe --config .\server.config.yaml server_service install
Get-Service AtlantiraptorServer
sc.exe qfailure AtlantiraptorServer
Get-NetTCPConnection -State Listen -LocalPort 8889
```

The install prints nothing when it works. Check the result with the
commands after it: the service must be **Running**, the failure actions
must show `RESTART`, and port 8889 must be listening.

The install:

1. stops and replaces an existing service of the same name,
2. copies the program to `install_path` and the configuration next to it
   as `AtlantiraptorServer.config.yaml`,
3. registers the service: LocalSystem, automatic start, restarted after a
   minute if it stops, running the server (the `frontend` command),
4. starts it.

If the service isn't running, look in the log folder, in the Windows
**Application** event log and see [Server problems](/troubleshooting/server/).

Then move `C:\AtlSetup\server.config.yaml` somewhere only administrators
can read and back it up: the service uses its own copy, and anyone with
the file can pretend to be your server. To change the configuration
later, edit `C:\Program Files\Atlantiraptor Server\AtlantiraptorServer.config.yaml`
and restart the service.

### 6. Sign in

Browse to `https://<server name>:8889/` and sign in as the administrator
the wizard created. With a self-signed configuration the console listens
on the server itself only (`GUI.bind_address: 127.0.0.1`), so open
`https://localhost:8889/` on the server, or reach it over a VPN or an SSH
tunnel. Then:

- set up [two-factor sign in](/deployment/authentication/#two-factor-sign-in),
- review **Server settings > Server updates** (see [Updating](/deployment/updates/)),
- [deploy agents](/deployment/clients/). The server runs no agent of its
  own; to monitor the server computer too, install an agent on it like on
  any other computer.

### Managing the service

Use **Services** (`services.msc`), `Stop-Service AtlantiraptorServer` and
`Start-Service AtlantiraptorServer`, or the program itself from the
install folder:

```powershell
cd 'C:\Program Files\Atlantiraptor Server'
.\AtlantiraptorServer.exe --config .\AtlantiraptorServer.config.yaml server_service stop
.\AtlantiraptorServer.exe --config .\AtlantiraptorServer.config.yaml server_service start
.\AtlantiraptorServer.exe --config .\AtlantiraptorServer.config.yaml server_service remove
```

Removing the service leaves the program, the configuration and the data
folder in place.

## Linux

Atlant Security publishes signed Windows binaries. On Linux, build the
server from source (below) or use a binary provided to you by Atlant
Security, then install it as a systemd service with a Debian or RPM
package that the program builds for you.

### Building from source

You need Go (the version in `go.mod`), Node.js 20 or later and `make`:

```sh
git clone https://github.com/atlantsecurity/atlantiraptor.git
cd atlantiraptor
cd gui/velociraptor && npm install && npm run build && cd ../..
go run make.go -v BasicAssets
go build -tags "server_vql extras release" -o atlantiraptor ./bin/
```

A binary built this way is a *development build*: it shows its version as
a development version and does not update itself.

### Installing with a package

Create the configuration with the wizard as on Windows:

```sh
./atlantiraptor config generate -i
```

Then build a package that contains the binary, the configuration and a
systemd unit, and install it:

```sh
# Debian, Ubuntu
./atlantiraptor --config server.config.yaml debian server --binary ./atlantiraptor
sudo dpkg -i atlantiraptor-server-*.deb

# RHEL, Rocky, Alma, Fedora
./atlantiraptor --config server.config.yaml rpm server --binary ./atlantiraptor
sudo rpm -i atlantiraptor-server-*.rpm
```

The package creates a system user, installs the configuration under
`/etc/velociraptor/`, keeps data in the datastore path from the
configuration (by default `/opt/velociraptor`), and starts the
`velociraptor_server` service. Check it with:

```sh
sudo systemctl status velociraptor_server
sudo journalctl -u velociraptor_server -f
```

To change the configuration later, edit `/etc/velociraptor/server.config.yaml`
and restart the service. Upgrades are installed the same way: build a new
package from the new binary and install it over the old one.

### Running without a package

For a test, or under another service manager, run the frontend directly:

```sh
./atlantiraptor --config server.config.yaml frontend -v
```

`-v` prints the log to the terminal. Run it as a dedicated, unprivileged
user that owns the datastore directory. If the frontend should listen on a
port below 1024 (for example 443), give the binary the
`CAP_NET_BIND_SERVICE` capability instead of running it as root.

## Checking that the server works

- The console loads at `https://<server>:8889/` and you can sign in.
- `https://<server>:8000/server.pem` returns the server certificate from an
  endpoint's network (this is how agents check reachability).
- After you install one agent, it appears on the dashboard under
  **Recently seen** within a minute.

If something does not work, see [Server problems](/troubleshooting/server/).

## Running the server in the cloud

Any cloud virtual machine works. A few points specific to the cloud:

- Give the machine a static public IP address and a DNS name, and use that
  name when you generate the configuration.
- Open the frontend port to the internet (endpoints connect from
  anywhere); open the console port only to your team's addresses in the
  cloud firewall, and also use [Network access](/deployment/network-access/).
- Put the datastore on a separate data disk, so you can resize it and take
  snapshots for [backups](/deployment/backups/).
- If a load balancer or proxy sits in front of the server, see
  [TLS certificates](/deployment/tls/#behind-a-reverse-proxy-or-load-balancer).

You can also keep the data in object storage and run several frontends;
see [Scaling out](/deployment/scaling/).
