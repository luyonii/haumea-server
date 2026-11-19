# redis_snapshot.ps1 — BGSAVE + encrypt (age) + copia offsite via robocopy.
# needs age installed and BACKUP_RECIPIENT env set to age pubkey (age1...). Private key stays offline.
# Env: REDIS_PASSWORD, OFFSITE, BACKUP_RECIPIENT. REDIS_HOST, REDIS_DIR opcionais.
[CmdletBinding()]
param(
    [string]$RedisHost   = $(if ($env:REDIS_HOST) { $env:REDIS_HOST } else { '127.0.0.1' }),
    [string]$RedisDir    = $(if ($env:REDIS_DIR)  { $env:REDIS_DIR }  else { 'C:\ProgramData\Redis' }),
    [string]$Offsite     = $env:OFFSITE
)

$ErrorActionPreference = 'Stop'
if (-not $env:REDIS_PASSWORD)       { throw 'REDIS_PASSWORD env obrigatorio' }
if (-not $Offsite)                  { throw 'OFFSITE env/param obrigatorio' }
if (-not $env:BACKUP_RECIPIENT)     { throw 'BACKUP_RECIPIENT (age pubkey) obrigatorio — nao exportar plaintext' }

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

    # Cifra em stage local, envia .age para offsite. Plaintext nao sai do host.
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("redis-snap-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        foreach ($name in @('dump.rdb','appendonly.aof')) {
            $src = Join-Path $RedisDir $name
            if (Test-Path $src) {
                & age -r $env:BACKUP_RECIPIENT -o (Join-Path $stage "$name.age") -- $src
                if ($LASTEXITCODE -ne 0) { throw "age falhou em $name (exit $LASTEXITCODE)" }
            }
        }
        robocopy $stage $Offsite '*.age' /NJH /NJS /NP /R:2 /W:5 | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "robocopy falhou (exit $LASTEXITCODE)" }
        Write-Output "snapshot ok -> $Offsite"
    }
    finally {
        Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    }
}
finally {
    Remove-Item Env:REDISCLI_AUTH -ErrorAction SilentlyContinue
}
