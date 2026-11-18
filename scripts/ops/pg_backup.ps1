# pg_backup.ps1 — daily logical dump + SHA-256 + rotate 30d (Windows admin host).
# Env: PGPASSWORD obrigatorio. PGHOST/PGUSER/PGDB opcionais.
[CmdletBinding()]
param(
    [string]$BackupDir = $(if ($env:BACKUP_DIR) { $env:BACKUP_DIR } else { 'C:\backup\postgres\daily' })
)

$ErrorActionPreference = 'Stop'

if (-not $env:PGPASSWORD) { throw 'PGPASSWORD env obrigatorio' }
$pgHost = if ($env:PGHOST) { $env:PGHOST } else { 'localhost' }
$pgUser = if ($env:PGUSER) { $env:PGUSER } else { 'secblind' }
$pgDb   = if ($env:PGDB)   { $env:PGDB }   else { 'secblind' }

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$file  = Join-Path $BackupDir "secblind-$stamp.dump"

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

# Dump custom format + compressao 6.
& pg_dump -h $pgHost -U $pgUser -Fc -Z 6 -d $pgDb -f $file
if ($LASTEXITCODE -ne 0) { throw "pg_dump falhou (exit $LASTEXITCODE)" }

# Checksum.
$hash = (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLower()
"$hash  $(Split-Path -Leaf $file)" | Out-File -Encoding ascii -FilePath "$file.sha256"

# Rotate 30d.
Get-ChildItem -Path $BackupDir -File -Filter 'secblind-*' |
    Where-Object { $_.LastWriteTimeUtc -lt (Get-Date).ToUniversalTime().AddDays(-30) } |
    Remove-Item -Force

Write-Output "backup ok: $file"
