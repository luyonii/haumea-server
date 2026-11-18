# rotate_cert_check.ps1 — compara SPKI SHA-256 do novo cert com pin1/pin2 em Project1/src/net.cpp.
# Requer openssl.exe no PATH.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$CertPath
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $CertPath)) { throw "cert nao encontrado: $CertPath" }

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$netCpp    = Join-Path $scriptDir '..\..\Project1\src\net.cpp'
if (-not (Test-Path $netCpp)) { throw "nao achei net.cpp em $netCpp" }

# Pipeline openssl: cert -> pubkey DER -> sha256 hex.
# Usa arquivo temp pq pipeline de bytes entre & openssl no PowerShell 5.1 e chato.
$tmpDer = [System.IO.Path]::GetTempFileName()
try {
    & openssl x509 -in $CertPath -pubkey -noout | & openssl pkey -pubin -outform DER -out $tmpDer
    if ($LASTEXITCODE -ne 0) { throw 'openssl falhou extraindo SPKI' }
    $newHash = (Get-FileHash -Algorithm SHA256 -Path $tmpDer).Hash.ToLower()
}
finally {
    Remove-Item -Force $tmpDer -ErrorAction SilentlyContinue
}

$netText = Get-Content -Raw -Path $netCpp
$pin1 = if ($netText -match 'pin1\s*=\s*OBF\("([0-9a-fA-F]{64})"\)') { $Matches[1].ToLower() } else { $null }
$pin2 = if ($netText -match 'pin2\s*=\s*OBF\("([0-9a-fA-F]{64})"\)') { $Matches[1].ToLower() } else { $null }

Write-Output "new SPKI sha256: $newHash"
$pin1Show = if ($pin1) { $pin1 } else { '<nao-extraido>' }
$pin2Show = if ($pin2) { $pin2 } else { '<nao-extraido>' }
Write-Output "pin1 (ativo):    $pin1Show"
Write-Output "pin2 (backup):   $pin2Show"

if ($newHash -eq $pin1) {
    Write-Output 'MATCH: bate com pin1 (ativo). Rotate seguro (sem efeito util).'
    exit 0
}
elseif ($newHash -eq $pin2) {
    Write-Output 'MATCH: bate com pin2 (backup). Rotate seguro. Gerar novo pin2 para proximo ciclo.'
    exit 0
}
else {
    Write-Error 'MISMATCH: novo cert nao bate com nenhum pin. ABORT rotate.'
    exit 1
}
