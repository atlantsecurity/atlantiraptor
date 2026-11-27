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
