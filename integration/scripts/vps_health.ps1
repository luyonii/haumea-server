#!/usr/bin/env pwsh
# Health-check VPS secblind. Rode do Windows: pwsh .\vps_health.ps1
$ErrorActionPreference = 'Continue'
$env:Path = "$env:Path;$env:LOCALAPPDATA\hcloud"

$tokenFile = 'C:\Users\SMTHFU~1\AppData\Local\Temp\claude\5966f551f9640513\9974769e-5e1d-4d6c-b816-264e160c5d6c\scratchpad\hcloud_token.txt'
if (Test-Path $tokenFile) {
    $env:HCLOUD_TOKEN = (Get-Content $tokenFile -Raw).Trim()
}

Write-Host '--- SSH + services ---' -ForegroundColor Cyan
ssh -o ConnectTimeout=10 secblind @"
set -e
uptime
echo '---'
docker --version
docker compose version
echo '---'
systemctl is-active docker fail2ban ssh secblind-server
echo '---'
sudo ufw status | head -20
echo '---'
sudo fail2ban-client status sshd 2>/dev/null | head -10 || echo 'fail2ban sshd jail not configured'
echo '--- secblind stack ---'
cd ~/secblind/integration && docker compose ps
echo '--- server tail ---'
sudo journalctl -u secblind-server -n 15 --no-pager
echo '--- nginx tail ---'
docker compose logs --tail=10 nginx 2>&1
echo '--- auth/challenge probe ---'
LKEY=\$(docker compose exec -T postgres psql -U secblind -d secblind -t -c 'SELECT license_key FROM licenses LIMIT 1;' | tr -d ' ')
if [ -n \"\$LKEY\" ]; then
  curl -sk -o /dev/null -w 'HTTP %{http_code} in %{time_total}s\n' -X POST https://127.0.0.1/api/v1/auth/challenge \
    -H 'Host: secblind.local' -H 'Content-Type: application/json' --data \"{\\\"license_key\\\":\\\"\$LKEY\\\"}\"
else
  echo 'no license in db'
fi
"@

Write-Host "`n--- Hetzner side ---" -ForegroundColor Cyan
if (Get-Command hcloud -ErrorAction SilentlyContinue) {
    hcloud server describe privgb-server -o 'format={{.Name}} status={{.Status}} ipv4={{.PublicNet.IPv4.IP}} firewalls={{len .PublicNet.Firewalls}}'
    Write-Host '--- Firewall rules ---'
    hcloud firewall describe secblind-public
} else {
    Write-Host 'hcloud CLI not in PATH' -ForegroundColor Yellow
}
