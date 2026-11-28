---
title: Installing the server
description: Install the Atlantiraptor server on Windows or Linux and run it as a service.
---

The server is the same `Atlantiraptor.exe` program as the agent, started
with a server configuration file. This page installs it as a service on
Windows or Linux. Before you start, read [Deploying Atlantiraptor](/deployment/)
and choose the DNS name, ports and certificate type.

## Windows

### 1. Prepare the machine

- Windows Server 2019 or later (x64), or Windows 10/11 for a small or lab
  deployment.
- A dedicated data folder on a fast disk, for example `D:\Atlantiraptor`.
- Firewall rules allowing the frontend port (8000 by default) from
  endpoints, and the console port (8889) from your analysts.

Download `Atlantiraptor-windows-amd64.exe` from the
[latest release](https://github.com/atlantsecurity/atlantiraptor/releases/latest),
check its signature, and save it as `Atlantiraptor.exe`:

```powershell
Get-AuthenticodeSignature .\Atlantiraptor.exe | Format-List Status, SignerCertificate
```

The status must be `Valid` and the signer `Atlant Security EOOD`.

### 2. Create the configuration

Run the interactive wizard and answer its questions (server operating
system, data folder, certificate type, public DNS name, ports, first
administrator):

```powershell
.\Atlantiraptor.exe config generate -i
```

It writes `server.config.yaml` and `client.config.yaml`. The server
configuration contains private keys: store it with restricted permissions
and keep a backup. See [Server configuration](/deployment/configuration/)
for what the wizard creates and how to change it later.

### 3. Name the service

Always run the server as a Windows service. It then starts with Windows,
keeps running when you sign out, restarts by itself if it stops, and
[updates itself](/deployment/updates/) without anyone signed in.

`server_service install` takes the service name and the install folder
from the `windows_installer` section under `Client` in the configuration.
The wizard's defaults (`Velociraptor`, `C:\Program Files\Velociraptor\`)
are also what a Velociraptor agent uses. Installing with them **stops,
overwrites and replaces** any service that already has that name. Give
the server its own name first. Open `server.config.yaml` in a text editor
and change the section to:

```yaml
Client:
  # ... other settings unchanged ...
  windows_installer:
    service_name: AtlantiraptorServer
    install_path: C:\Program Files\Atlantiraptor Server\AtlantiraptorServer.exe
    service_description: Atlantiraptor server
```

Check that no service has that name yet:

```powershell
Get-Service | Where-Object { $_.Name -match 'raptor' }
```

Also check that `Logging.output_directory` is set to a folder (the wizard
sets it). A service has no console window, so without it the server's log
goes nowhere. See [Server logging](/deployment/logging/).

### 4. Install the service (as administrator)

Installing a service needs administrator rights. Click **Start**, type
`PowerShell`, right-click **Windows PowerShell** and choose **Run as
administrator**. Then, in the folder with `Atlantiraptor.exe` and the
configuration:

1. Stop anything else that runs this server, such as a `gui` lab in
   another window or a scheduled task. Ports 8000 and 8889 must be free:

   ```powershell
   Get-NetTCPConnection -State Listen -LocalPort 8000,8889 -ErrorAction SilentlyContinue
   ```

   This prints nothing when the ports are free.

2. Install and start the service:

   ```powershell
   .\Atlantiraptor.exe --config server.config.yaml server_service install
   ```

   This copies the program to `install_path` and the configuration next to
   it, as `AtlantiraptorServer.config.yaml`. It then registers the service
   (automatic start, runs as LocalSystem, restarts 60 seconds after a
   failure) and starts it. If a service with the same name already exists,
   it replaces it.

3. Check it:

   ```powershell
   Get-Service AtlantiraptorServer
   sc.exe qfailure AtlantiraptorServer
   Get-NetTCPConnection -State Listen -LocalPort 8889
   ```

   The service must be `Running`, the failure actions must show `RESTART`,
   and port 8889 must be listening.

The service reads the configuration copy in the install folder, not the
file you started from. To change a setting later, edit the original
`server.config.yaml` and run step 2 again, which reinstalls the service
with the new copy.

Manage the service from an administrator PowerShell with
`Restart-Service AtlantiraptorServer` or `Stop-Service` /
`Start-Service`, or with the Windows Services console. To remove it, run
`.\Atlantiraptor.exe --config server.config.yaml server_service remove`.
This keeps the datastore.

> **Note:** The server and the agent are named by the same configuration
> keys. The agent MSI always installs a service called `Atlantiraptor`,
> so with the server named `AtlantiraptorServer` both can run on the same
> machine.

### 5. Sign in

Browse to `https://<server name>:8889/` and sign in as the administrator
the wizard created. Then:

- set up [two-factor sign in](/deployment/authentication/#two-factor-sign-in),
- review **Server settings > Server updates** (see [Updating](/deployment/updates/)),
- [deploy agents](/deployment/clients/).

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
