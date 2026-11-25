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

- The Windows agent and server are one binary. A Release build is
  `go build -tags "velomain server_vql extras disable_grpc_modules goexperiment.nojsonv2 release yara"`
  with the `bin/rsrc_windows_*.syso` resources in place, written to `dist/release/`.
  Sign that folder; never sign `output/` (local development builds, rebuilt constantly).
- There is no MSI build in this repo yet. When one is added, sign the MSI after building it.
