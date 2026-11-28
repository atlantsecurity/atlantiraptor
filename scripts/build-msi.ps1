#Requires -Version 7
<#
.SYNOPSIS
    Builds the Atlantiraptor endpoint agent MSI (Atlant Security).

.DESCRIPTION
    Order (see CLAUDE.md): build the Release binary, sign it with
    sign-agents.ps1, then run this script, then sign the MSI with
    sign-agents.ps1 and verify.

    The client config is an input. It is adapted for the install location:
    writeback and temp folders under "Program Files\Atlant Security\Atlantiraptor"
    and the Windows service name "Atlantiraptor". Its server address is
    kept as given, so it must be the address endpoints can reach.

    Needs WiX v5 (dotnet tool install --global wix) and the Util extension
    (wix extension add -g WixToolset.Util.wixext/5.0.2).

.EXAMPLE
    pwsh -File scripts/build-msi.ps1 -Binary dist/release/Atlantiraptor.exe -ClientConfig client.config.yaml -Version 1.0.0
#>
param(
    [Parameter(Mandatory = $true)] [string] $Binary,
    [Parameter(Mandatory = $true)] [string] $ClientConfig,
    [Parameter(Mandatory = $true)] [ValidatePattern('^\d+\.\d+\.\d+$')] [string] $Version,
    [string] $OutDir = 'dist/release',
    [switch] $AllowUnsigned
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

foreach ($p in @($Binary, $ClientConfig)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "Not found: $p" }
}
$sig = Get-AuthenticodeSignature -LiteralPath $Binary
if ($sig.Status -ne 'Valid' -and -not $AllowUnsigned) {
    throw "The binary is not signed (status $($sig.Status)). Sign it first with scripts/sign-agents.ps1."
}

$config = Get-Content -LiteralPath $ClientConfig -Raw
if ($config -notmatch '(?m)^Client:' -or $config -notmatch 'server_urls:') {
    throw "$ClientConfig does not look like a client config (no Client.server_urls)."
}
if ($config -match '(?m)^\s*private_key:') {
    throw "$ClientConfig contains a private key. Use the client config, not the server config."
}

# Adapt paths and the service name for this installer.
$base = '$ProgramFiles\Atlant Security\Atlantiraptor'
$replacements = [ordered]@{
    '(?m)^(\s*writeback_windows:).*$' = "`$1 $base\atlantiraptor.writeback.yaml"
    '(?m)^(\s*tempdir_windows:).*$'   = "`$1 $base\Tools"
}
foreach ($r in $replacements.GetEnumerator()) {
    if ($config -match $r.Key) { $config = $config -replace $r.Key, $r.Value }
}
$installer = @"
  windows_installer:
    service_name: Atlantiraptor
    install_path: $base\Atlantiraptor.exe
    service_description: Atlantiraptor endpoint agent by Atlant Security
"@
if ($config -match '(?ms)^  windows_installer:\r?\n(    .*\r?\n)+') {
    $config = $config -replace '(?ms)^  windows_installer:\r?\n(    [^\r\n]*\r?\n)+', ($installer + "`n")
} else {
    $config = $config -replace '(?m)^Client:\r?\n', ("Client:`n" + $installer + "`n")
}
foreach ($k in 'writeback_windows', 'tempdir_windows') {
    if ($config -notmatch "(?m)^\s*$k\s*:") {
        $value = if ($k -eq 'writeback_windows') { "$base\atlantiraptor.writeback.yaml" } else { "$base\Tools" }
        $config = $config -replace '(?m)^Client:\r?\n', ("Client:`n  ${k}: $value`n")
    }
}

$stage = Join-Path ([IO.Path]::GetTempPath()) ("atlantiraptor-msi-{0}" -f [guid]::NewGuid())
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    Copy-Item -LiteralPath $Binary -Destination (Join-Path $stage 'Atlantiraptor.exe')
    [IO.File]::WriteAllText((Join-Path $stage 'client.config.yaml'), $config, (New-Object System.Text.UTF8Encoding $false))
    Copy-Item -LiteralPath (Join-Path $repo 'LICENSE') -Destination (Join-Path $stage 'LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $repo 'docs/wix/atlantiraptor_amd64.wxs') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $repo 'docs/wix/icon.ico') -Destination $stage

    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $out = Join-Path (Resolve-Path $OutDir) "Atlantiraptor-$Version-amd64.msi"
    Push-Location $stage
    try {
        & wix build atlantiraptor_amd64.wxs -arch x64 -ext WixToolset.Util.wixext -d "Version=$Version" -o $out
        if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }
    } finally { Pop-Location }
    Write-Host "Built $out"
    Write-Host "Next: pwsh -File scripts/sign-agents.ps1 -Path `"$out`" -Description `"Atlantiraptor`""
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
