# Atlantiraptor

## Code signing (Azure Artifact Signing)

Release builds of the Windows agents must be Authenticode-signed with Atlant Security's
Azure Artifact Signing account before they are packaged or shipped.

- Account: `atlantsecurity-signing` (North Europe, endpoint `https://neu.codesigning.azure.net`)
- Certificate profile: `atlant-public-trust`
- Windows: `scripts/sign-agents.ps1` (SignTool + Artifact Signing dlib)
- macOS/Linux: `scripts/sign-agents.sh` (Jsign)
- Authentication: the developer's own `az login` session. If signing fails with an
  authentication or 403 error, stop and ask the user to run
  `az login --tenant atlantsecurity.com` or check their role assignment. Never create
  service principals, client secrets, or Azure role assignments yourself.

### Rules

1. Sign every Release build as part of building it; no need to ask the user first.
   Never sign Debug, test, or experimental builds: every file counts against a
   5,000-signatures-per-month quota.
2. Order: build -> sign our own .exe/.dll/.ps1 -> build the MSI -> sign the MSI -> verify.
3. Never sign third-party binaries (vcruntime, OpenSSL, etc.). The PowerShell script
   skips files that already have a valid signature; do not pass `-Force` unless the user asks.
4. Never sign kernel drivers (.sys/.cat). Drivers go through Microsoft Hardware Dev Center
   attestation signing, which is a separate, manual process the user handles.
5. If you're unsure which files a folder contains, check with a dry run first
   (`-WhatIf` / `--dry-run`); it uses no quota.
6. After signing, report the verification output. The signer must be Atlant Security's
   legal entity name and every file must have a timestamp.
7. Do not edit the signing scripts' endpoint, account, or profile without asking.

### Examples

```powershell
# SIEM agent binaries, then installer
pwsh -File scripts/sign-agents.ps1 -Path build/Release/siem-agent -Recurse -Description "Atlant SIEM Agent"
pwsh -File scripts/sign-agents.ps1 -Path dist/AtlantSiemAgent.msi -Description "Atlant SIEM Agent"

# DLP agent (user-mode parts only; the driver goes to Hardware Dev Center)
pwsh -File scripts/sign-agents.ps1 -Path build/Release/dlp-agent -Recurse -Description "Atlant DLP Agent"
```

```bash
# Same thing from macOS/Linux
scripts/sign-agents.sh -n "Atlant SIEM Agent" -r build/Release/siem-agent
```

### In this repository

- The Windows agent and server are one binary. Version resources (product Atlantiraptor,
  Atlant Security EOOD, AGPL attribution) come from `docs/winres/winres_template.json`:
  set the version and run `go-winres make --in docs/winres/winres.json --out bin/rsrc`.
  A Release build is
  `go build -tags "velomain server_vql extras disable_grpc_modules goexperiment.nojsonv2 release yara"`
  with the `bin/rsrc_windows_*.syso` resources in place, written to `dist/release/`.
  Sign that folder; never sign `output/` (local development builds, rebuilt constantly).
- Releases and self-update: servers install the latest GitHub release of this repository by
  themselves (`services/selfupdate`, console page Admin > Server updates). A release needs
  `Atlantiraptor-windows-amd64.exe` built with
  `-X www.velocidex.com/golang/velociraptor/config.release_version=x.y.z` (otherwise it is a
  development build that never auto-updates), signed, plus a `SHA256SUMS` file.
  `.github/workflows/release.yml` publishes one per merge to master once Azure federated
  credentials are configured; until then run `pwsh -File scripts/publish-release.ps1` on the
  developer PC (build -> sign -> verify -> `gh release create`). Servers refuse any binary
  that isn't Authenticode-signed by Atlant Security EOOD and trusted by Windows.
- MSI: `scripts/build-msi.ps1 -Binary dist/release/Atlantiraptor.exe -ClientConfig <client.config.yaml> -Version x.y.z`
  (WiX v5, source `docs/wix/atlantiraptor_amd64.wxs`). Order: build exe -> sign exe ->
  build MSI -> sign MSI -> verify. Keep the UpgradeCode unchanged so new versions upgrade in place.
- Premium hunt feeds (`services/huntfeeds`, console page Hunt feeds, spec in `docs/feeds/README.md`):
  servers fetch Atlant's signed hunt packs with the customer's licence key. Feeds are
  verified against the Ed25519 keys in `services/huntfeeds/keys.go`; never add a key there
  that wasn't generated for Atlant's feed service, and never commit a private key.
