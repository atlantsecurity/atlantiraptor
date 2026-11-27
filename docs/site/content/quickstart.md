---
title: Quick start
description: Run a complete Atlantiraptor server and agent on one computer, then try a collection and a hunt.
---

The quickest way to see Atlantiraptor working is the `gui` command. It
starts a server, a web console and an agent together on your own computer,
with a self-signed certificate and an administrator account. Nothing is
installed, and everything is kept in one folder you can delete afterwards.

Use this to learn and to test artifacts. For a real deployment, follow
[Deploying Atlantiraptor](/deployment/).

## 1. Download

Download `Atlantiraptor-windows-amd64.exe` from the
[latest release](https://github.com/atlantsecurity/atlantiraptor/releases/latest)
and save it as `Atlantiraptor.exe`. Every release binary is signed by
Atlant Security EOOD; you can check this under **Properties > Digital
Signatures** in Windows Explorer, or with:

```powershell
Get-AuthenticodeSignature .\Atlantiraptor.exe | Format-List Status, SignerCertificate
```

On Linux or macOS, build the binary from source (see
[Installing the server](/deployment/server/#building-from-source)).

## 2. Start it

Open a terminal as an administrator (the agent needs administrator rights to
see the whole system) and run:

```powershell
.\Atlantiraptor.exe gui
```

The first run creates a data folder (by default under your temporary
folder; add `--datastore C:\AtlantiraptorLab` to choose one), writes a
server and client configuration into it, and opens the console in your
browser at `https://127.0.0.1:8889/`. The browser warns about the
self-signed certificate; accept it for this local address.

Sign in as `admin` with the password `password`. These credentials only
work from this computer, because the `gui` server listens on 127.0.0.1.

## 3. Look around

- The **Dashboard** shows connected clients, running hunts and server
  health. Your own computer is the one connected client.
- Click the computer under **Recently seen** to open its **host page**.
  Try a **Quick triage** tile, for example *Processes*, and watch the
  results arrive.
- Press <kbd>Ctrl</kbd>+<kbd>K</kbd> to open the command palette. Paste a
  domain you visited today, such as `github.com`, and choose
  **Hunt for this indicator**: Rapid hunt asks every client (here, one)
  whether it visited it.

## 4. Run a collection

1. On the host page, open **Collections** (in the **Client** part of the
   sidebar) and click **Collect**.
2. Search for `Generic.Client.Info` and select it.
3. Click **Collect now**. The results appear in a few seconds, with one tab per
   artifact source.
4. Click **All files as zip** to download everything the collection
   gathered.

## 5. Run a hunt

1. Open **Hunts** and click **New hunt**.
2. Pick `Windows.System.Pslist` (or `Linux.Sys.Pslist` on Linux).
3. Leave the target as all clients and click **Create and start hunt**.
4. Open the hunt to see results from every client that answered, and its
   notebook for analysis.

## 6. Clean up

Stop the program with <kbd>Ctrl</kbd>+<kbd>C</kbd>. To start again from
scratch, delete the data folder.

## Next steps

- Learn the vocabulary in [Key concepts](/concepts/).
- Explore the [console](/console/).
- Write your first query in [VQL fundamentals](/vql/fundamentals/).
- Plan a production deployment in [Deploying Atlantiraptor](/deployment/).
