# Cross-compile the Linux admin server, scp it to the VPS and restart the
# systemd unit, failing closed on every step. Run from the repo root.
#
# Usage: .\dist\deploy-server.ps1  [-Host root@65.108.60.114]  [-SkipBuild]
param(
    [string]$RemoteHost = "root@65.108.60.114",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$binPath  = Join-Path $repoRoot "dist\server-linux"
$srcPath  = Join-Path $repoRoot "server"

if (-not $SkipBuild) {
    Write-Host "[build] linux/amd64..." -ForegroundColor Cyan
    Push-Location $srcPath
    try {
        $env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
        if (Test-Path $binPath) { Remove-Item $binPath -Force }
        & go build -ldflags="-s -w" -o $binPath ./cmd/server
        if ($LASTEXITCODE -ne 0) { throw "go build failed" }
    } finally {
        Pop-Location
        Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path $binPath)) { throw "binary missing: $binPath" }
$size = (Get-Item $binPath).Length
Write-Host "[build] $size bytes" -ForegroundColor Green

Write-Host "[scp] -> ${RemoteHost}:/tmp/server-new..." -ForegroundColor Cyan
& scp $binPath "${RemoteHost}:/tmp/server-new"
if ($LASTEXITCODE -ne 0) { throw "scp failed" }

Write-Host "[remote] swap + restart + validate..." -ForegroundColor Cyan
$remoteScript = @'
set -e
BIN=/home/sam/secblind/bin/server
cp "$BIN" "${BIN}.bak.$(date +%s)"
mv /tmp/server-new "$BIN"
chown sam:sam "$BIN"
chmod +x "$BIN"
systemctl restart secblind-server
sleep 2
systemctl is-active secblind-server
ss -tlnp | grep -E ':8080|:8443|:9090'
'@
& ssh $RemoteHost $remoteScript
if ($LASTEXITCODE -ne 0) { throw "remote deploy failed" }

Write-Host "[done]" -ForegroundColor Green
