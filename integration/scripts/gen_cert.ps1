# Generate self-signed leaf cert for secblind.local, export DER+PEM+key,
# print SHA-256 of the DER (what the client pins).
# Run from any PowerShell (no VS tools required). Admin NOT required.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$certDir = Join-Path (Split-Path -Parent $here) 'nginx\cert'
New-Item -ItemType Directory -Force -Path $certDir | Out-Null

$cn = 'secblind.local'

# Create in CurrentUser\My, 825 days, RSA 2048 (fine for TLS 1.3 pin test).
$cert = New-SelfSignedCertificate `
    -Subject "CN=$cn" `
    -DnsName $cn `
    -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddDays(825) `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyExportPolicy Exportable `
    -Provider 'Microsoft Software Key Storage Provider'

$derPath = Join-Path $certDir 'leaf.der'
$crtPath = Join-Path $certDir 'leaf.crt'   # PEM for nginx
$keyPath = Join-Path $certDir 'leaf.key'   # PEM key for nginx
$pfxPath = Join-Path $certDir 'leaf.pfx'

# DER (what the client pins)
[IO.File]::WriteAllBytes($derPath, $cert.RawData)

# PEM cert
$b64 = [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
"-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----" |
    Set-Content -Path $crtPath -Encoding ascii

# Export PFX, then use openssl in a throwaway container to extract the PEM
# private key. PowerShell 5.1 ships .NET 4.8 which lacks ExportPkcs8PrivateKey.
$pwd = ConvertTo-SecureString -String 'secblind-dev' -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd | Out-Null

docker run --rm -v "${certDir}:/cert" alpine/openssl pkcs12 `
    -in /cert/leaf.pfx -nocerts -nodes -out /cert/leaf.key `
    -passin pass:secblind-dev | Out-Null
if ($LASTEXITCODE -ne 0) { throw "openssl conversion failed (exit=$LASTEXITCODE)" }

Remove-Item $pfxPath -Force

# SHA-256 of leaf DER
$sha = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha.ComputeHash($cert.RawData)
$hex = -join ($hashBytes | ForEach-Object { '{0:x2}' -f $_ })

# Clean up cert store entry (we only needed the files)
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force

Write-Host ""
Write-Host "Cert written to: $crtPath"
Write-Host "Key  written to: $keyPath"
Write-Host "DER  written to: $derPath"
Write-Host ""
Write-Host "Leaf DER SHA-256:"
Write-Host $hex
Write-Host ""
Write-Host "If this differs from pin_leaf_current at Project1\src\net.cpp:166, replace both pins (:166 and :169) with the new hash and rebuild Project1 (x64 Release)."
