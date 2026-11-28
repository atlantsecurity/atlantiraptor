# Atlantiraptor

Atlantiraptor is an endpoint and cloud breach hunting platform by
[Atlant Security](https://atlantsecurity.com). An agent on each endpoint
answers questions written in VQL; a central server sends the questions,
collects the answers and keeps them for investigation. The same tool
covers triage, threat hunting, forensic collection, continuous monitoring,
response, and read-only breach hunting in Microsoft 365 / Entra ID, Google
Workspace, Okta and AWS tenants.

**Documentation: <https://atlantsecurity.github.io/atlantiraptor/>**

Atlantiraptor is based on the open source
[Velociraptor](https://github.com/Velocidex/velociraptor) project and is
distributed under the same licence, the GNU Affero General Public License
v3 (see [LICENSE](LICENSE)). It adds a redesigned console, guided
investigation workflows, cloud breach hunting, premium hunt feeds, an
integration REST API and signed automatic updates.

## Quick start

Download `Atlantiraptor-windows-amd64.exe` from the
[latest release](https://github.com/atlantsecurity/atlantiraptor/releases/latest)
(or build it, below), save it as `Atlantiraptor.exe`, and run as an
administrator:

```powershell
.\Atlantiraptor.exe gui
```

This starts a server, the console and an agent on your own machine, and
opens the console in your browser. See the
[quick start](https://atlantsecurity.github.io/atlantiraptor/quickstart/)
and, for a real deployment,
[Deploying](https://atlantsecurity.github.io/atlantiraptor/deployment/).

## Deploy a client

An agent connects to your server with the server's **client
configuration**: the server address, the certificate authority it trusts,
and the org's enrollment nonce (the shared secret that lets it enroll).
The configuration is created together with the server; each agent then
makes its own key the first time it starts.

1. Set up a server that other computers can reach (see
   [Set up a test lab, part B](https://atlantsecurity.github.io/atlantiraptor/quickstart/#b-a-server-and-a-second-computer)
   or [Deploying](https://atlantsecurity.github.io/atlantiraptor/deployment/)).
   The one-computer `gui` lab only listens on `localhost`.
2. In the console, open **Clients** and expand **Deploy a client** at the
   bottom of the page (server administrators only).
3. Pick **Windows**, **Linux**, **macOS** or **Microsoft Intune**, and copy
   the command into the computer you want to add:
   - **Windows**: paste it into PowerShell run as administrator. It
     downloads the signed `Atlantiraptor-windows-amd64.exe` for your
     server's version from the GitHub release, refuses it unless it is
     signed by Atlant Security EOOD, and installs the `Atlantiraptor`
     service. The same installer is available as `Install-Atlantiraptor.ps1`
     for Group Policy, SCCM or RMM tools.
   - **Linux / macOS**: put the `atlantiraptor` program for that system in
     a folder and paste the command into a terminal there (uses `sudo`);
     it installs a systemd service or a launchd daemon.
   - **Microsoft Intune**: download `Atlantiraptor-Intune.intunewin` and
     `Detect-Atlantiraptor.ps1` and add them as a Win32 app; the tab lists
     the install and uninstall commands and settings. See
     [Deploying with Intune](https://atlantsecurity.github.io/atlantiraptor/deployment/intune/).
4. Within a minute the computer appears under **Clients**.

Without the console, get the configuration with
`Atlantiraptor.exe --config server.config.yaml config client > client.config.yaml`
and install with the [MSI](https://atlantsecurity.github.io/atlantiraptor/deployment/clients/#the-msi-installer-recommended)
or `Atlantiraptor.exe --config client.config.yaml service install`.
Treat the client configuration like a password: anyone who has it can
enroll a computer to your server.

## Building from source

You need Go (see `go.mod`), Node.js LTS, `make`, and `gcc` for CGO
(mingw-w64 to build Windows binaries on Linux).

```bash
git clone https://github.com/atlantsecurity/atlantiraptor.git
cd atlantiraptor

# The console
cd gui/velociraptor && npm install && make build && cd ../..

# A development binary in output/
make
```

Release builds of the Windows binary and MSI are built, Authenticode-signed
and published by `scripts/publish-release.ps1` or
`.github/workflows/release.yml`; deployed servers install new releases by
themselves (see
[Updating](https://atlantsecurity.github.io/atlantiraptor/deployment/updates/)).

## Documentation

The documentation website is built from [`docs/site`](docs/site/README.md)
and published to GitHub Pages on every merge to master. The reference
sections (VQL, artifacts, configuration, command line, REST API) are
generated from this repository, so fixing a description in the source
fixes the website too.

## Getting help

- Support for customers: <https://atlantsecurity.com>
- Bugs and feature requests: [GitHub issues](https://github.com/atlantsecurity/atlantiraptor/issues)
- Security problems: see [security.md](security.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
