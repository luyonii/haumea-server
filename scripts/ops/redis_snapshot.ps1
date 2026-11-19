# redis_snapshot.ps1 — BGSAVE + copia offsite via robocopy/rsync.
# Env: REDIS_PASSWORD, OFFSITE (caminho UNC/local destino). REDIS_HOST, REDIS_DIR opcionais.
[CmdletBinding()]
param(
    [string]$RedisHost   = $(if ($env:REDIS_HOST) { $env:REDIS_HOST } else { '127.0.0.1' }),
    [string]$RedisDir    = $(if ($env:REDIS_DIR)  { $env:REDIS_DIR }  else { 'C:\ProgramData\Redis' }),
    [string]$Offsite     = $env:OFFSITE
)

$ErrorActionPreference = 'Stop'
if (-not $env:REDIS_PASSWORD) { throw 'REDIS_PASSWORD env obrigatorio' }
if (-not $Offsite)            { throw 'OFFSITE env/param obrigatorio' }

# redis-cli le REDISCLI_AUTH do ambiente: senha fora de argv/Get-Process.
$env:REDISCLI_AUTH = $env:REDIS_PASSWORD
Remove-Item Env:REDIS_PASSWORD

function Invoke-Redis($args) {
    $out = & redis-cli -h $RedisHost --no-auth-warning @args
    if ($LASTEXITCODE -ne 0) { throw "redis-cli falhou: $args" }
    return $out
}

try {
    $before = Invoke-Redis @('LASTSAVE')
    Invoke-Redis @('BGSAVE') | Out-Null

    # Poll ate 120s.
    $ok = $false
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 2
        if ((Invoke-Redis @('LASTSAVE')) -ne $before) { $ok = $true; break }
    }
    if (-not $ok) { throw 'BGSAVE nao concluiu em 120s' }

    # Copia arquivos (robocopy nao falha em "nothing to copy").
    robocopy $RedisDir $Offsite 'dump.rdb' 'appendonly.aof' /NJH /NJS /NP /R:2 /W:5 | Out-Null
    Write-Output "snapshot ok -> $Offsite"
}
finally {
    Remove-Item Env:REDISCLI_AUTH -ErrorAction SilentlyContinue
}
