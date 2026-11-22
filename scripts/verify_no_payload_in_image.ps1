# verify_no_payload_in_image.ps1 — baseline scaffold for Phase C enforcement.
#
# Scans the built loader image for ASCII / UTF-16LE occurrences of the
# payload-handling signatures the Phase B refactor must remove. Expected
# to FAIL today (loader still does fetch+decrypt+PE-map in-process); the
# same script is expected to PASS after Phase B moves that work into the
# target process.
#
# Usage:
#   .\scripts\verify_no_payload_in_image.ps1
#   .\scripts\verify_no_payload_in_image.ps1 -Image "C:\path\to\Project1.exe"
#   .\scripts\verify_no_payload_in_image.ps1 -Soft      # report, exit 0
#
# Exit codes:
#   0  No matches (or -Soft).
#   1  At least one match found.
#   2  Image not found / read error.

param(
    [string] $Image,
    [switch] $Soft
)

$ErrorActionPreference = 'Stop'

if (-not $Image) {
    $candidates = @(
        (Join-Path $PSScriptRoot '..\Project1\x64\Release\Project1.exe'),
        (Join-Path $PSScriptRoot '..\Project1\Release\Project1.exe'),
        (Join-Path $PSScriptRoot '..\x64\Release\Project1.exe'),
        (Join-Path $PSScriptRoot '..\Release\Project1.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $Image = $c; break }
    }
}

if (-not $Image -or -not (Test-Path $Image)) {
    Write-Host "verify_no_payload_in_image: image not found." -ForegroundColor Red
    Write-Host "  Pass -Image <path> or build a Release first." -ForegroundColor Red
    exit 2
}

$needles = @(
    'AES-GCM',
    '/payload/fetch',
    'ciphertext',
    'watermark',
    'BCRYPT_AES',
    'payload_fetch'
)

try {
    $bytes = [System.IO.File]::ReadAllBytes($Image)
} catch {
    Write-Host "verify_no_payload_in_image: read error: $_" -ForegroundColor Red
    exit 2
}

$asciiText   = [System.Text.Encoding]::ASCII.GetString($bytes)
$unicodeText = [System.Text.Encoding]::Unicode.GetString($bytes)

$hits = New-Object System.Collections.ArrayList
foreach ($needle in $needles) {
    foreach ($pair in @(,@('ASCII', $asciiText), ,@('UTF-16LE', $unicodeText))) {
        $enc = $pair[0]; $txt = $pair[1]
        $pos = 0
        while (($pos = $txt.IndexOf($needle, $pos, [System.StringComparison]::OrdinalIgnoreCase)) -ge 0) {
            [void]$hits.Add([pscustomobject]@{
                Encoding = $enc
                Needle   = $needle
                Offset   = ('0x{0:X}' -f $pos)
            })
            $pos += $needle.Length
        }
    }
}

Write-Host '=== verify_no_payload_in_image ==='
Write-Host ("Image:   {0}" -f $Image)
Write-Host ("Needles: {0}" -f ($needles -join ', '))
Write-Host ''

if ($hits.Count -eq 0) {
    Write-Host 'PASS: zero matches.' -ForegroundColor Green
    exit 0
}

$hits | Format-Table -AutoSize
Write-Host ''
if ($Soft) {
    Write-Host ("REPORT ONLY: {0} match(es). Rerun without -Soft to enforce." -f $hits.Count) -ForegroundColor Yellow
    exit 0
}
Write-Host ("FAIL: {0} match(es). This is expected during Phase A; must be clean after Phase B." -f $hits.Count) -ForegroundColor Yellow
exit 1
