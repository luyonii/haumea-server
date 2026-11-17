# Launch 5 loader instances in parallel to flush out races in the pre-auth path
# (net critsec init, heartbeat start/stop, sentinel start/stop). All instances
# will fail auth — that's fine; the point is thread-safety under concurrency.
# Usage: .\stress_sentinel.ps1 -Path .\Project1\x64\Release\Project1.exe

param([Parameter(Mandatory=$true)][string]$Path)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Path)) {
    Write-Host "File not found: $Path" -ForegroundColor Red
    exit 2
}

$procs = @()
for ($i = 0; $i -lt 5; $i++) {
    $p = Start-Process -FilePath $Path -PassThru -WindowStyle Hidden
    if ($p) { $procs += $p }
}

$deadline = (Get-Date).AddSeconds(10)
$hung     = @()
foreach ($p in $procs) {
    $remainMs = [int]([Math]::Max(0, ($deadline - (Get-Date)).TotalMilliseconds))
    if (-not $p.WaitForExit($remainMs)) {
        $hung += $p.Id
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {}
    }
}

Write-Host "Launched: $($procs.Count)"
foreach ($p in $procs) {
    if ($hung -contains $p.Id) {
        Write-Host "  PID $($p.Id): HANG (process still running - may be stdin-wait or genuine race)" -ForegroundColor Yellow
    } else {
        Write-Host "  PID $($p.Id): exit=$($p.ExitCode)"
    }
}

if ($hung.Count -gt 0) {
    Write-Host "FAIL: $($hung.Count) hung" -ForegroundColor Red
    exit 1
}
Write-Host "PASS: all exited within 10s" -ForegroundColor Green
exit 0
