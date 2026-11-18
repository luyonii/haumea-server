# Sec-blind load runner (PowerShell).
# Usage:
#   pwsh tests/load/run_all.ps1            # full suite
#   pwsh tests/load/run_all.ps1 -Quick     # only baseline + login
#   pwsh tests/load/run_all.ps1 -Out json  # also dump summary-*.json per run

param(
    [switch]$Quick,
    [ValidateSet('none','json')]
    [string]$Out = 'none'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command k6 -ErrorAction SilentlyContinue)) {
    Write-Error "k6 not on PATH. Install: choco install k6 (or see README)."
    exit 2
}

if (-not $env:SB_BASE_URL) { $env:SB_BASE_URL = 'http://127.0.0.1:8080' }
if (-not $env:SB_LICENSES) {
    Write-Warning "SB_LICENSES not set — scenarios that need licenses will fail. See README."
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$scripts = if ($Quick) {
    @('00_baseline.js','01_login_flow.js')
} else {
    @('00_baseline.js','01_login_flow.js','02_heartbeat_sustained.js',
      '03_rpc_burst.js','04_rate_limit_hit.js','05_payload_fetch_concurrency.js')
}

$fail = 0
foreach ($s in $scripts) {
    $path = Join-Path $here $s
    Write-Host "=== $s ===" -ForegroundColor Cyan
    $args = @('run', $path)
    if ($Out -eq 'json') {
        $summary = Join-Path $here ("summary-" + [IO.Path]::GetFileNameWithoutExtension($s) + ".json")
        $args += @('--summary-export', $summary)
    }
    & k6 @args
    if ($LASTEXITCODE -ne 0) { $fail++ ; Write-Warning "$s failed (exit $LASTEXITCODE)" }
}

if ($fail -gt 0) { Write-Error "$fail scenario(s) failed thresholds."; exit 1 }
Write-Host "All scenarios passed." -ForegroundColor Green
