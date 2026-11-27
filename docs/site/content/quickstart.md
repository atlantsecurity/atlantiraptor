---
title: Set up a test lab
description: Get an Atlantiraptor server and agent running in ten minutes - everything on one computer, or a server plus a second computer.
---

To use Atlantiraptor you need two things running: the **server** (which
also serves the console, the web page you work in) and at least one
**agent** on a computer you want to look at. Both are the same program,
`Atlantiraptor.exe`.

Pick one of two test setups:

- **[A. Everything on one computer](#a-everything-on-one-computer)**:
  one command, two minutes. The server, the console and an agent all run
  on your own Windows computer. Best for a first look.
- **[B. A server and a second computer](#b-a-server-and-a-second-computer)**:
  about ten minutes. Closer to the real thing: the agent on one computer
  reports to the server on another.

Both are for testing. Nothing here is hardened for production; for that,
see [Deploying Atlantiraptor](/deployment/) once you know the basics.

## Download the program

Download `Atlantiraptor-windows-amd64.exe` from the
[latest release](https://github.com/atlantsecurity/atlantiraptor/releases/latest),
create a folder such as `C:\AtlLab`, and save the file there as
`Atlantiraptor.exe`.

It is signed by Atlant Security EOOD. To check, right-click it, choose
**Properties > Digital Signatures**, and look for that name.

## A. Everything on one computer

**1.** Click **Start**, type `PowerShell`, right-click **Windows PowerShell**
and choose **Run as administrator**. (The agent needs administrator
rights to see the whole computer.)

**2.** Run:

```powershell
cd C:\AtlLab
.\Atlantiraptor.exe gui
```

**3.** Your browser opens the console at `https://127.0.0.1:8889/`. It warns
that the certificate is not trusted, because the lab made its own.
Choose **Advanced** and continue to the page.

**4.** Sign in as `admin` with the password `password`. This account only
works from this computer.

Your own computer is now the one connected client: you can see it on the
dashboard under **Recently seen**.

To stop, press <kbd>Ctrl</kbd>+<kbd>C</kbd> in the PowerShell window.
Everything the lab stored is in a data folder under your temporary folder;
run `.\Atlantiraptor.exe gui --datastore C:\AtlLab\data` instead to keep it
in a folder you choose, and delete that folder to start again from
scratch.

Next: [Your first Rapid hunt](/first-hunt/).

## B. A server and a second computer

You need two Windows computers on the same network: one for the server,
and one with the agent (the *client*). A virtual machine works for either.

### On the server computer

**1.** Open PowerShell **as administrator** and find this computer's IP
address:

```powershell
cd C:\AtlLab
ipconfig
```

Note the **IPv4 Address**, for example `192.168.1.10`.

**2.** Create the configuration with the setup wizard:

```powershell
.\Atlantiraptor.exe config generate -i
```

Use the arrow keys and Enter to answer. For a lab:

| Question | Answer |
|---|---|
| Deployment Type | **Self Signed SSL** |
| What OS will the server be deployed on? | **Windows** |
| Datastore and logs directories | Keep the suggestions, or type `C:\AtlLab\data` |
| Public DNS name | This computer's IP address, for example `192.168.1.10` |
| DNS Type | **None - Configure DNS manually** |
| Websocket comms | **No** |
| Frontend port, GUI port | Keep `8000` and `8889` |
| Admin user | A user name and password for you |
| Anything else | Keep the default |

The wizard saves two files: `server.config.yaml` (for the server; it
holds private keys, keep it to yourself) and `client.config.yaml` (for
agents).

**3.** Let agents reach the server through the Windows firewall:

```powershell
New-NetFirewallRule -DisplayName "Atlantiraptor agents" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

**4.** Start the server, and leave the window open:

```powershell
.\Atlantiraptor.exe --config server.config.yaml frontend -v
```

**5.** On the same computer, open `https://127.0.0.1:8889/` in a browser,
accept the certificate warning, and sign in with the user you created.
In this lab setup the console only answers on the server computer
itself.

### On the second computer

**1.** Copy `Atlantiraptor.exe` and **`client.config.yaml`** (not the server
configuration) into a folder such as `C:\AtlLab`.

**2.** Open PowerShell **as administrator** and start the agent:

```powershell
cd C:\AtlLab
.\Atlantiraptor.exe --config client.config.yaml client -v
```

The window shows it connecting and enrolling. Leave it open.

**3.** Within a minute the computer appears in the console on the server, on
the dashboard under **Recently seen** and under **Clients**.

If it doesn't appear, check that the second computer can reach the
server's port 8000 (`Test-NetConnection 192.168.1.10 -Port 8000`), and
read the messages in the agent's window. More help is in
[Agent problems](/troubleshooting/clients/).

To keep the agent running after you close the window, install it as a
service instead:

```powershell
.\Atlantiraptor.exe --config client.config.yaml service install
```

For many computers, use the installer: see
[Add more computers](/tasks/add-computers/).

## Next step

[Your first Rapid hunt](/first-hunt/): ask your computers whether they have
seen a website.
