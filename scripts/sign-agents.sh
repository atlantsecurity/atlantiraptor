#!/usr/bin/env bash
# Sign Atlant Security Windows agent binaries from macOS/Linux with Azure Artifact Signing (via Jsign).
#
# Prereqs: Jsign 6+ (brew install jsign, or https://github.com/ebourg/jsign/releases), Azure CLI,
#          and once per machine: az login --tenant atlantsecurity.com
# Usage:   scripts/sign-agents.sh [-n "Atlant SIEM Agent"] [-r] [--dry-run] <file-or-dir>...
#
# Each file signed = 1 signature against the monthly quota (Basic: 5,000).
# Kernel drivers (.sys/.cat) are skipped: they need Hardware Dev Center attestation signing.
# Directories: only .exe .dll .msi .msix .appx .ps1 .psm1 .psd1 are picked up.
# Jsign can't check existing signatures here, so point it at your own build outputs only,
# not at folders that also contain vendor-signed third-party DLLs.
# Config via env: ARTIFACT_SIGNING_ENDPOINT, ARTIFACT_SIGNING_ACCOUNT, ARTIFACT_SIGNING_PROFILE, ARTIFACT_SIGNING_URL
set -euo pipefail

ENDPOINT="${ARTIFACT_SIGNING_ENDPOINT:-neu.codesigning.azure.net}"
ACCOUNT="${ARTIFACT_SIGNING_ACCOUNT:-atlantsecurity-signing}"
PROFILE="${ARTIFACT_SIGNING_PROFILE:-atlant-public-trust}"
URL="${ARTIFACT_SIGNING_URL:-https://atlantsecurity.com}"
NAME=""
RECURSE=0
DRY_RUN=0

usage() { echo "usage: $0 [-n name] [-r] [--dry-run] <file-or-dir>..." >&2; }

paths=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--name)    NAME="$2"; shift 2 ;;
    -r|--recurse) RECURSE=1; shift ;;
    --dry-run)    DRY_RUN=1; shift ;;
    -h|--help)    sed -n '2,14p' "$0"; exit 0 ;;
    -*)           echo "unknown option: $1" >&2; usage; exit 2 ;;
    *)            paths+=("$1"); shift ;;
  esac
done
if [[ ${#paths[@]} -eq 0 ]]; then usage; exit 2; fi

# Jsign wants the bare host name.
ENDPOINT="${ENDPOINT#https://}"
ENDPOINT="${ENDPOINT%/}"

files=()
add_file() {
  local f="$1" mode="${2:-}" lower
  lower="$(printf '%s' "$f" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *.sys|*.cat)
      echo "WARN: skipping kernel driver file (Hardware Dev Center required): $f" >&2 ;;
    *.exe|*.dll|*.msi|*.msix|*.appx|*.ps1|*.psm1|*.psd1)
      files+=("$f") ;;
    *)
      if [[ "$mode" == "explicit" ]]; then echo "WARN: skipping unsupported file type: $f" >&2; fi ;;
  esac
}

for p in "${paths[@]}"; do
  if [[ -d "$p" ]]; then
    if [[ $RECURSE -eq 1 ]]; then
      while IFS= read -r -d '' f; do add_file "$f"; done < <(find "$p" -type f -print0)
    else
      while IFS= read -r -d '' f; do add_file "$f"; done < <(find "$p" -maxdepth 1 -type f -print0)
    fi
  elif [[ -f "$p" ]]; then
    add_file "$p" explicit
  else
    echo "ERROR: not found: $p" >&2
    exit 1
  fi
done

echo "Files to sign: ${#files[@]} (= ${#files[@]} signatures of monthly quota)"
if [[ ${#files[@]} -eq 0 ]]; then exit 0; fi
printf '  %s\n' "${files[@]}"
if [[ $DRY_RUN -eq 1 ]]; then echo "Dry run: nothing was signed."; exit 0; fi

command -v jsign >/dev/null 2>&1 || { echo "ERROR: jsign not found (brew install jsign)" >&2; exit 1; }
command -v az    >/dev/null 2>&1 || { echo "ERROR: Azure CLI (az) not found" >&2; exit 1; }

if ! TOKEN="$(az account get-access-token --resource https://codesigning.azure.net --query accessToken -o tsv 2>/dev/null)" || [[ -z "$TOKEN" ]]; then
  echo "ERROR: no Azure token. Run: az login --tenant atlantsecurity.com" >&2
  exit 1
fi

args=(--storetype TRUSTEDSIGNING --keystore "$ENDPOINT" --storepass "$TOKEN" --alias "$ACCOUNT/$PROFILE" --replace)
if [[ -n "$NAME" ]]; then args+=(--name "$NAME"); fi
if [[ -n "$URL" ]];  then args+=(--url "$URL"); fi

# One invocation for all files (Jsign timestamps automatically for Artifact Signing).
jsign "${args[@]}" "${files[@]}"
echo "Signed ${#files[@]} file(s). Check on Windows with: signtool verify /pa /v <file>"
