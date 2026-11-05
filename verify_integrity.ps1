param(
    [string]$ManifestFile = "SHA256SUMS.txt",
    [switch]$CanonicalOnly
)

$ErrorActionPreference = "Stop"
$RootDir = $PSScriptRoot
Set-Location -LiteralPath $RootDir

Write-Host "==============================================================================="
Write-Host "Blockchain + AI Digital Forensics - Cryptographic Integrity Verification"
Write-Host "Target Root: $RootDir"
Write-Host "==============================================================================="

$CanonicalDbs = @{
    "data/forensics.db"    = "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001"
    "data/real_p4.db"      = "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97"
    "data/benchmark_p6.db" = "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507"
}

$Failed = 0
foreach ($Entry in $CanonicalDbs.GetEnumerator()) {
    $Rel = $Entry.Key
    $Expected = $Entry.Value
    $FullPath = Join-Path $RootDir ($Rel -replace "/", "\")
    if (-not (Test-Path -LiteralPath $FullPath)) {
        Write-Host "[FAIL] Canonical DB missing: $Rel" -ForegroundColor Red
        $Failed++
        continue
    }
    $Actual = (Get-FileHash -LiteralPath $FullPath -Algorithm SHA256).Hash.ToUpper()
    if ($Actual -ne $Expected) {
        Write-Host "[FAIL] Canonical DB mismatch: $Rel (got $Actual, expected $Expected)" -ForegroundColor Red
        $Failed++
    } else {
        Write-Host "[PASS] Canonical DB intact: $Rel ($($Actual.Substring(0, 16))...)"
    }
}

if ($CanonicalOnly) {
    if ($Failed -gt 0) { exit 1 }
    Write-Host "[OK] Canonical database invariance verified (3/3 MATCH)."
    exit 0
}

$ManifestPath = Join-Path $RootDir $ManifestFile
if (-not (Test-Path -LiteralPath $ManifestPath)) {
    Write-Host "[FAIL] Integrity manifest not found: $ManifestPath" -ForegroundColor Red
    exit 1
}

$Lines = Get-Content -LiteralPath $ManifestPath -Encoding UTF8 | Where-Object { $_.Trim().Length -gt 0 }
if ($Lines.Count -eq 0) {
    Write-Host "[FAIL] Integrity manifest is empty: $ManifestPath" -ForegroundColor Red
    exit 1
}

$Checked = 0
foreach ($Line in $Lines) {
    if ($Line -match "^([0-9A-Fa-f]{64})\s+\*?(.+)$") {
        $ExpectedSha = $Matches[1].ToUpper()
        $RelFile = $Matches[2].Trim()
        $TargetFile = Join-Path $RootDir ($RelFile -replace "/", "\")
        $Checked++
        if (-not (Test-Path -LiteralPath $TargetFile)) {
            Write-Host "[FAIL] MISSING: $RelFile" -ForegroundColor Red
            $Failed++
            continue
        }
        $ActualSha = (Get-FileHash -LiteralPath $TargetFile -Algorithm SHA256).Hash.ToUpper()
        if ($ActualSha -ne $ExpectedSha) {
            Write-Host "[FAIL] MISMATCH: $RelFile (got $ActualSha, expected $ExpectedSha)" -ForegroundColor Red
            $Failed++
        }
    } else {
        Write-Host "[FAIL] Malformed manifest line: $Line" -ForegroundColor Red
        $Failed++
    }
}

if ($Failed -gt 0) {
    Write-Host "==============================================================================="
    Write-Host "INTEGRITY VERIFICATION FAILED ($Failed error(s) across $Checked manifest entries)" -ForegroundColor Red
    Write-Host "==============================================================================="
    exit 1
}

Write-Host "[PASS] Verified $Checked/$Checked manifest files in $ManifestFile"
Write-Host "==============================================================================="
Write-Host "INTEGRITY VERIFICATION PASSED (100% SHA-256 CONCORDANCE)"
Write-Host "==============================================================================="
exit 0
