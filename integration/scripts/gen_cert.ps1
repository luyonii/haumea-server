# Generate CA-marked self-signed leaf cert for secblind.local (basicConstraints
# CA:TRUE critical, so Windows schannel accepts it in LocalMachine\Root for
# WinHTTP integration tests), export DER+PEM+key, print SHA-256 of the DER
# (what the client pins). Run from any PowerShell. Admin NOT required.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$certDir = Join-Path (Split-Path -Parent $here) 'nginx\cert'
New-Item -ItemType Directory -Force -Path $certDir | Out-Null

$cn = 'secblind.local'

$derPath = Join-Path $certDir 'leaf.der'
$crtPath = Join-Path $certDir 'leaf.crt'
$keyPath = Join-Path $certDir 'leaf.key'
$cfgPath = Join-Path $certDir 'openssl.cnf'

$cfg = @"
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = $cn
[v3]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$cn
"@
Set-Content -Path $cfgPath -Value $cfg -Encoding ascii

docker run --rm -v "${certDir}:/c" alpine/openssl req -x509 -newkey rsa:2048 -nodes `
    -keyout /c/leaf.key -out /c/leaf.crt -days 825 -config /c/openssl.cnf -outform PEM | Out-Null
if ($LASTEXITCODE -ne 0) { Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue; throw "openssl req failed (exit=$LASTEXITCODE)" }

docker run --rm -v "${certDir}:/c" alpine/openssl x509 -in /c/leaf.crt -outform DER -out /c/leaf.der | Out-Null
if ($LASTEXITCODE -ne 0) { Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue; throw "openssl DER conversion failed (exit=$LASTEXITCODE)" }

Remove-Item $cfgPath -Force

# SHA-256 of leaf DER
$hashBytes = (Get-FileHash $derPath -Algorithm SHA256).Hash
$hex = $hashBytes.ToLower()

Write-Host ""
Write-Host "Cert written to: $crtPath"
Write-Host "Key  written to: $keyPath"
Write-Host "DER  written to: $derPath"
Write-Host ""
Write-Host "Leaf DER SHA-256:"
Write-Host $hex
Write-Host ""
Write-Host "If this differs from pin_leaf_current at Project1\src\net.cpp:166, replace both pins (:166 and :169) with the new hash and rebuild Project1 (x64 Release)."
