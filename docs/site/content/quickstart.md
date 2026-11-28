---
title: Set up a test lab
description: Install the Atlantiraptor server as a Windows service and connect an agent, in about fifteen minutes.
---

To use Atlantiraptor you need two things running: the **server** (which
also serves the console, the web page you work in) and at least one
**agent** on a computer you want to look at. Both are the same program,
`Atlantiraptor.exe`, and both run as Windows services, so they keep
running after you close PowerShell and start again when Windows restarts.

This lab needs one Windows computer for the server. The agent can run on
the same computer, on a second one, or on both. A virtual machine works
for either. Nothing here is hardened for production; for that, see
[Deploying Atlantiraptor](/deployment/) once you know the basics.

## Install the server

Do every step on the server computer, in one PowerShell window opened
**as administrator**: click **Start**, type `PowerShell`, right-click
**Windows PowerShell** and choose **Run as administrator**. Installing a
service needs administrator rights.

**1. Download the program.** Make a folder for the lab and download the
latest release into it:

```powershell
New-Item -ItemType Directory -Force C:\AtlLab | Out-Null
cd C:\AtlLab
Invoke-WebRequest -UseBasicParsing -OutFile Atlantiraptor.exe `
  https://github.com/atlantsecurity/atlantiraptor/releases/latest/download/Atlantiraptor-windows-amd64.exe
```

**2. Check the signature.** Only run the program if it is signed by
Atlant Security:

```powershell
Get-AuthenticodeSignature .\Atlantiraptor.exe | Format-List Status, SignerCertificate
```

`Status` must be `Valid` and the signer must be `Atlant Security EOOD`.
If it isn't, delete the file and download it again from the
[releases page](https://github.com/atlantsecurity/atlantiraptor/releases/latest).

**3. Create the configuration** with the setup wizard:

```powershell
.\Atlantiraptor.exe config generate -i
```

Use the arrow keys and Enter to answer. For a lab:

| Question | Answer |
|---|---|
| Deployment Type | **Self Signed SSL** |
| What OS will the server be deployed on? | **Windows** |
| Datastore and logs directories | Keep the suggestions, or type `C:\AtlLab\data` |
| Public DNS name | `localhost` if the agent will only run on this computer. Otherwise this computer's IP address, for example `192.168.1.10`; `ipconfig` shows it as **IPv4 Address**. |
| DNS Type | **None - Configure DNS manually** |
| Websocket comms | **No** |
| Frontend port, GUI port | Keep `8000` and `8889` |
| Admin user | A user name and password for you |
| Anything else | Keep the default |

The wizard saves `server.config.yaml`, which holds the server's private
keys, and `client.config.yaml`. You won't need `client.config.yaml`: the
console gives you a ready-made install command for agents in step 8.

**4. Give the server service its own name.** The configuration names the
service `Velociraptor` and installs it under `C:\Program Files\Velociraptor`.
Name it `AtlantiraptorServer` instead, so it can't be confused with an
agent:

```powershell
(Get-Content .\server.config.yaml) `
  -replace 'service_name: Velociraptor$', 'service_name: AtlantiraptorServer' `
  -replace 'install_path: \$ProgramFiles\\Velociraptor\\Velociraptor\.exe$', 'install_path: C:\Program Files\Atlantiraptor Server\AtlantiraptorServer.exe' `
  -replace 'service_description: Velociraptor service$', 'service_description: Atlantiraptor server' |
  Set-Content .\server.config.yaml
Select-String -Path .\server.config.yaml -Pattern 'service_name|install_path' | Select-Object -First 2
```

The last command should show `AtlantiraptorServer` and
`C:\Program Files\Atlantiraptor Server\AtlantiraptorServer.exe`. Never use
`Atlantiraptor` as the server's service name: that is the agent's service.

**5. Install and start the service:**

```powershell
.\Atlantiraptor.exe --config .\server.config.yaml server_service install
Get-Service AtlantiraptorServer
```

The install copies the program and the configuration to
`C:\Program Files\Atlantiraptor Server\`, registers the
`AtlantiraptorServer` service (it starts automatically with Windows and
restarts if it stops) and starts it. `Get-Service` should show
**Running**. If it doesn't, see [Server problems](/troubleshooting/server/).

**6. Put the configuration away.** The service uses its own copy in the
install folder. Move `C:\AtlLab\server.config.yaml` somewhere only
administrators can read, and keep it as a backup: anyone who has it can
pretend to be your server.

**7. Open the console.** On the server computer, browse to
`https://localhost:8889/`. The browser warns that the certificate is not
trusted, because the lab made its own: choose **Advanced** and continue.
Sign in with the user you created in step 3. In this lab the console only
answers on the server computer itself.

## Connect an agent

The server alone has nothing to look at. Install an agent on the server
computer, on another computer, or on both.

**8. Copy the install command.** In the console, open **Server settings >
Deploy a client**, pick the **Windows** tab and click **Copy** next to the
PowerShell command.

**9. Run it on the computer you want to add**, in PowerShell opened as
administrator. It downloads the signed program, checks the signature,
and installs and starts the `Atlantiraptor` agent service.

Within a minute the computer appears on the dashboard under **Recently
seen** and under **Clients**.

### Agents on other computers {#b-a-server-and-a-second-computer}

For an agent on another computer, the server's Public DNS name in step 3
must be the server's IP address, not `localhost`. Then let agents through
the Windows firewall on the **server** computer:

```powershell
New-NetFirewallRule -DisplayName "Atlantiraptor agents" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

If the computer doesn't appear, check from it that the server's port 8000
answers (`Test-NetConnection 192.168.1.10 -Port 8000`). More help is in
[Agent problems](/troubleshooting/clients/). For many computers, see
[Add more computers](/tasks/add-computers/).

## Stop, start or remove the lab

Use **Services** (`services.msc`) or PowerShell as administrator:

```powershell
Stop-Service AtlantiraptorServer
Start-Service AtlantiraptorServer
```

To remove the server service:

```powershell
cd 'C:\Program Files\Atlantiraptor Server'
.\AtlantiraptorServer.exe --config .\AtlantiraptorServer.config.yaml server_service remove
```

Then delete that folder and the data folder you chose in step 3. To
remove an agent, download `Install-Atlantiraptor.ps1` from **Server
settings > Deploy a client** and run it as administrator with
`-Uninstall`.

## Next step

[Your first Rapid hunt](/first-hunt/): ask your computers whether they have
seen a website.
