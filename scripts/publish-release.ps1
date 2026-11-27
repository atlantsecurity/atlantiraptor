#Requires -Version 7
<#
.SYNOPSIS
    Build, sign and publish an Atlantiraptor release on GitHub, from a
    developer PC.

.DESCRIPTION
    Deployed servers install the latest GitHub release by themselves
    (services/selfupdate). This script produces such a release when
    the GitHub Actions release workflow can't sign (it needs Azure
    federated credentials) or when you want to publish by hand:

      1. builds the GUI and the Windows server binary with the release
         version embedded (config.release_version and the version
         resource),
      2. signs it with scripts/sign-agents.ps1 (your az login session),
      3. verifies it exactly the way servers will before installing it
         (signature trusted by Windows, Atlant Security signer, version),
      4. writes SHA256SUMS and creates the GitHub release vX.Y.Z with
         both files (GitHub CLI, gh).

    Requires: Go, Node.js/npm, a C compiler for cgo (gcc), go-winres,
    the Azure CLI signed in (az login --tenant atlantsecurity.com),
    and gh signed in with access to atlantsecurity/atlantiraptor.

.EXAMPLE
    pwsh -File scripts/publish-release.ps1
    Publishes the next patch version from the current master commit.

.EXAMPLE
    pwsh -File scripts/publish-release.ps1 -Version 1.1.0 -NoPublish
    Builds, signs and verifies 1.1.0 into dist/release without publishing.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+$')] [string] $Version,
    [switch] $NoPublish,
    [switch] $SkipGui,
    # Publish from a commit that is not origin/master.
    [switch] $AllowAnyCommit
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'atlantsecurity/atlantiraptor'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
Push-Location $Root
try {
    function Need($cmd) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd not found on PATH" }
    }
    Need go; Need git
    if (-not $SkipGui) { Need npm }
    if (-not $NoPublish) {
        Need gh
        gh auth status *> $null
        if ($LASTEXITCODE -ne 0) { throw 'gh is not signed in: run gh auth login' }
    }
    $winres = (Get-Command go-winres -ErrorAction SilentlyContinue)?.Source
    if (-not $winres) {
        $winres = Join-Path (go env GOPATH) 'bin\go-winres.exe'
        if (-not (Test-Path $winres)) {
            Write-Host 'Installing go-winres...'
            go install github.com/tc-hib/go-winres@v0.3.3
        }
    }

    git fetch -q origin master --tags
    $commit = (git rev-parse HEAD).Trim()
    if (-not $AllowAnyCommit) {
        $master = (git rev-parse origin/master).Trim()
        if ($commit -ne $master) { throw "HEAD ($commit) is not origin/master ($master). Check out master or pass -AllowAnyCommit." }
    }

    if (-not $Version) {
        $tags = @(git tag -l 'v*')
        if (-not $NoPublish) { $tags += @(gh release list --repo $Repo --limit 100 --json tagName --jq '.[].tagName') }
        $latest = $tags | Where-Object { $_ -match '^v\d+\.\d+\.\d+$' } |
            Sort-Object { [version]$_.TrimStart('v') } | Select-Object -Last 1
        if (-not $latest) { $latest = 'v1.0.0' }
        $v = [version]$latest.TrimStart('v')
        $Version = "$($v.Major).$($v.Minor).$($v.Build + 1)"
    }
    if (-not $NoPublish) {
        gh release view "v$Version" --repo $Repo *> $null
        if ($LASTEXITCODE -eq 0) { throw "Release v$Version already exists" }
    }
    Write-Host "Building Atlantiraptor $Version from $commit" -ForegroundColor Cyan

    if (-not $SkipGui) {
        Push-Location gui/velociraptor
        try {
            npm ci --no-audit --no-fund; if ($LASTEXITCODE) { throw 'npm ci failed' }
            npm run build; if ($LASTEXITCODE) { throw 'GUI build failed' }
        } finally { Pop-Location }
    }

    go run make.go -v BasicAssets; if ($LASTEXITCODE) { throw 'assets failed' }
    & $winres make --in docs/winres/winres.json --out bin/rsrc --file-version "$Version.0" --product-version "$Version.0"
    if ($LASTEXITCODE) { throw 'go-winres failed' }

    $out = 'dist/release'
    New-Item -ItemType Directory -Force $out | Out-Null
    $exe = Join-Path $out 'Atlantiraptor-windows-amd64.exe'
    $short = (git rev-parse --short HEAD).Trim()
    $now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $pkg = 'www.velocidex.com/golang/velociraptor/config'
    $ldflags = "-w -s -X $pkg.release_version=$Version -X $pkg.build_time=$now -X $pkg.commit_hash=$short"
    $env:CGO_ENABLED = '1'; $env:GOOS = 'windows'; $env:GOARCH = 'amd64'
    go build -o $exe -tags 'velomain server_vql extras disable_grpc_modules goexperiment.nojsonv2 release yara' -ldflags $ldflags ./bin/
    if ($LASTEXITCODE) { throw 'go build failed' }

    # The resource files are checked in; keep the working tree clean.
    git checkout -- bin/rsrc_windows_386.syso bin/rsrc_windows_amd64.syso 2>$null

    & pwsh -File scripts/sign-agents.ps1 -Path $exe -Description 'Atlantiraptor'
    if ($LASTEXITCODE) { throw 'signing failed (run az login --tenant atlantsecurity.com?)' }

    $sig = Get-AuthenticodeSignature $exe
    $sig | Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
    if ($sig.Status -ne 'Valid') { throw "signature status: $($sig.Status)" }
    if (-not $sig.TimeStamperCertificate) { throw 'signature has no timestamp' }
    & $exe selfupdate verify $exe; if ($LASTEXITCODE) { throw 'selfupdate verify failed' }
    $reported = (& $exe selfupdate version).Trim()
    if ($reported -ne $Version) { throw "binary reports '$reported', expected $Version" }

    $hash = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower()
    $sums = Join-Path $out 'SHA256SUMS'
    # sha256sum format, LF line endings.
    [IO.File]::WriteAllText($sums, "$hash  Atlantiraptor-windows-amd64.exe`n")
    Write-Host "SHA256  $hash"

    if ($NoPublish) {
        Write-Host "Built, signed and verified $exe (not published)." -ForegroundColor Green
        return
    }
    gh release create "v$Version" $exe $sums --repo $Repo --target $commit --title "Atlantiraptor $Version" --generate-notes
    if ($LASTEXITCODE) { throw 'gh release create failed' }
    Write-Host "Published v$Version. Servers pick it up at their next check." -ForegroundColor Green
}
finally {
    Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}
