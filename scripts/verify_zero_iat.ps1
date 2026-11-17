# Verify compiled loader's import table against the zero-IAT policy baseline.
# Usage: .\verify_zero_iat.ps1 -Path .\Project1\x64\Release\Project1.exe
# Requires dumpbin (run from Developer PowerShell for VS, or with VsDevCmd loaded).

param([Parameter(Mandatory=$true)][string]$Path)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command dumpbin -ErrorAction SilentlyContinue)) {
    Write-Host "dumpbin.exe not found in PATH. Run from a Developer PowerShell." -ForegroundColor Red
    exit 2
}

if (-not (Test-Path $Path)) {
    Write-Host "File not found: $Path" -ForegroundColor Red
    exit 2
}

# APIs that MUST NEVER appear in the IAT. All of these are resolved dynamically.
$hardFail = @(
    'BCryptDecrypt','BCryptOpenAlgorithmProvider','BCryptHashData',
    'WinHttpOpen','WinHttpConnect','WinHttpSendRequest',
    'NtQueryInformationProcess','NtQuerySystemInformation','NtSetInformationThread',
    'GetAdaptersAddresses','RegOpenKeyExA',
    'LoadLibraryA','LoadLibraryW','GetProcAddress',
    'VirtualAlloc','VirtualProtect','VirtualFree',
    # 'IsDebuggerPresent' intentionally removed: the MSVC CRT pulls it in via
    # __scrt_fastfail / _invoke_watson. anti_debug.cpp uses PEB.BeingDebugged
    # directly and never calls this API, so an IAT entry here is CRT noise.
    'CheckRemoteDebuggerPresent','GetThreadContext',
    'FlushInstructionCache','OutputDebugStringA'
)

# Baseline DLLs expected from CRT-driven imports.
$allowedDlls = @('KERNEL32.dll','VCRUNTIME140.dll')

$dump = & dumpbin /imports $Path 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "dumpbin failed (exit=$LASTEXITCODE). Run from Developer PowerShell for VS." -ForegroundColor Red
    Write-Host $dump
    exit 2
}

$hits         = @()
$policyWarn   = @()
$currentDll   = $null

foreach ($line in $dump) {
    if ($line -match '^\s*([A-Za-z0-9_\-\.]+\.dll)\s*$') {
        $currentDll = $Matches[1]
        $isAllowed = ($allowedDlls -contains $currentDll) -or ($currentDll -like 'api-ms-win-crt-*.dll')
        if ($isAllowed) {
            Write-Host "DLL (allowed):           $currentDll" -ForegroundColor Green
        } else {
            $policyWarn += $currentDll
            Write-Host "DLL (policy deviation):  $currentDll" -ForegroundColor Yellow
        }
        continue
    }
    if ($currentDll -and $line -match '^\s+[0-9A-Fa-f]+\s+([A-Za-z_][A-Za-z0-9_]+)') {
        $fn = $Matches[1]
        if ($hardFail -contains $fn) {
            Write-Host "  HARD-FAIL: $fn (via $currentDll)" -ForegroundColor Red
            $hits += "$currentDll!$fn"
        } else {
            Write-Host "  $fn"
        }
    }
}

Write-Host ""
if ($hits.Count -gt 0) {
    Write-Host "FAIL: $($hits.Count) blacklisted import(s) — grep source for each function name." -ForegroundColor Red
    $hits | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "PASS: no blacklisted imports." -ForegroundColor Green
if ($policyWarn.Count -gt 0) {
    Write-Host "Note: $($policyWarn.Count) DLL(s) outside baseline — review." -ForegroundColor Yellow
}
exit 0
