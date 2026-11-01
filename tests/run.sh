#!/usr/bin/env bash
# Smoke tests for the scanner against tests/fixtures. Needs the .NET 10 SDK and jq.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
scripts="$here/../skills/dotnet-eol-guard/scripts"
fixture="$here/fixtures/legacy-app"
out="$(mktemp -d)"
fail() { echo "FAIL: $*" >&2; exit 1; }

cd "$scripts"

# Arrange / Act: full scan on a fixed date so the expectations do not drift
set +e
dotnet run eol-guard.cs -- --path "$fixture" --as-of 2026-10-31 --offline --format json --out "$out/full.json"
code=$?
set -e

# Assert
[ "$code" -eq 1 ] || fail "expected exit 1 with critical findings, got $code"
j="$out/full.json"
[ "$(jq '.summary.critical' "$j")" -ge 5 ] || fail "expected at least 5 critical findings"
jq -e '.target.channel == "10.0"' "$j" >/dev/null || fail "expected target 10.0"
jq -e '.findings[] | select(.category=="runtime" and .file=="src/Legacy.Api/Legacy.Api.csproj" and .severity=="critical")' "$j" >/dev/null || fail "net6.0 TFM not critical"
jq -e '.findings[] | select(.category=="runtime" and .current=="net8.0" and .severity=="high")' "$j" >/dev/null || fail "net8.0 not flagged as expiring"
jq -e '.findings[] | select(.category=="sdk" and .current=="8.0.100")' "$j" >/dev/null || fail "global.json not flagged"
jq -e '[.findings[] | select(.category=="container")] | length == 2' "$j" >/dev/null || fail "expected 2 container findings"
jq -e '[.findings[] | select(.category=="ci")] | length == 3' "$j" >/dev/null || fail "expected 3 CI pins"
jq -e '.findings[] | select(.category=="package-runtime" and .subject=="Microsoft.AspNetCore.Authentication.JwtBearer")' "$j" >/dev/null || fail "aligned package not flagged"
jq -e '.findings[] | select(.category=="package-vulnerable" and .subject=="Newtonsoft.Json" and .current=="12.0.1")' "$j" >/dev/null || fail "vulnerable Newtonsoft.Json not found"
jq -e '.findings[] | select(.category=="package-deprecated" and .subject=="WindowsAzure.Storage")' "$j" >/dev/null || fail "deprecated package not found"

# Arrange / Act / Assert: report-only mode never fails the build
dotnet run eol-guard.cs -- --path "$fixture" --as-of 2026-10-31 --offline --no-packages --fail-on none --out "$out/report.md" \
  || fail "--fail-on none must exit 0"
grep -q "Recommended target: \*\*.NET 10.0 (LTS)\*\*" "$out/report.md" || fail "markdown report missing target"

# Arrange / Act / Assert: before .NET 8/9 EOL with a short window, 8.0 is not flagged
dotnet run eol-guard.cs -- --path "$fixture" --as-of 2026-01-01 --warn-days 30 --offline --no-packages --format json --out "$out/early.json" || true
jq -e '[.findings[] | select(.current=="net8.0" and .severity!="info")] | length == 0' "$out/early.json" >/dev/null || fail "net8.0 flagged too early"

echo "lifecycle tests passed"

# Patch-level runtime CVEs need the live release metadata; skipped without network.
if curl -sf -o /dev/null https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json; then
  # Arrange / Act
  dotnet run eol-guard.cs -- --path "$here/fixtures/patched-app" --no-packages --fail-on none \
    --cve CVE-2026-111497,CVE-2026-96951 --format json --out "$out/patch.json"
  p="$out/patch.json"
  # Assert
  jq -e '[.findings[] | select(.category=="runtime-patch")] | length >= 3' "$p" >/dev/null || fail "pinned patches not flagged"
  jq -e '.findings[] | select(.category=="runtime-patch" and .subject=="RuntimeFrameworkVersion")' "$p" >/dev/null || fail "RuntimeFrameworkVersion pin not flagged"
  jq -e '.findings[] | select(.category=="cve" and .subject=="CVE-2026-111497" and .severity=="high")' "$p" >/dev/null || fail "Brotli CVE not reported as exposed"
  jq -e '.findings[] | select(.category=="cve" and .subject=="CVE-2026-96951" and .severity=="info")' "$p" >/dev/null || fail "non-.NET CVE not reported as out of scope"
  echo "patch-level tests passed"
else
  echo "skipping patch-level tests (no network)"
fi

# Out-of-support channels count as exposed to runtime CVEs (no fix will ever ship for them).
if curl -sf -o /dev/null https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json; then
  # Arrange / Act
  dotnet run eol-guard.cs -- --path "$fixture" --no-packages --fail-on none --cve CVE-2026-111497 --format json --out "$out/eol-cve.json"
  # Assert
  jq -e '.findings[] | select(.category=="cve" and .severity=="high" and (.message | contains("will not ship this fix")))' "$out/eol-cve.json" >/dev/null \
    || fail "EOL runtime not reported as exposed to a runtime CVE"
  echo "eol exposure tests passed"
fi
