# pg_backup.ps1 — daily logical dump, encrypted at rest + SHA-256 + rotate 30d (Windows admin host).
# needs age installed and BACKUP_RECIPIENT env set to age pubkey (age1...). Private key stays offline.
# Env: PGPASSWORD, BACKUP_RECIPIENT. PGHOST/PGUSER/PGDB opcionais.
[CmdletBinding()]
param(
    [string]$BackupDir = $(if ($env:BACKUP_DIR) { $env:BACKUP_DIR } else { 'C:\backup\postgres\daily' })
)

$ErrorActionPreference = 'Stop'

if (-not $env:PGPASSWORD)         { throw 'PGPASSWORD env obrigatorio' }
if (-not $env:BACKUP_RECIPIENT)   { throw 'BACKUP_RECIPIENT (age pubkey) obrigatorio — nao gerar plaintext' }
$pgHost = if ($env:PGHOST) { $env:PGHOST } else { 'localhost' }
$pgUser = if ($env:PGUSER) { $env:PGUSER } else { 'secblind' }
$pgDb   = if ($env:PGDB)   { $env:PGDB }   else { 'secblind' }

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$file  = Join-Path $BackupDir "secblind-$stamp.dump.age"

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

# Dump custom + compressao 6, cifrado via age (pipe binario, sem plaintext em disco).
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'pg_dump'
$psi.ArgumentList.Add('-h'); $psi.ArgumentList.Add($pgHost)
$psi.ArgumentList.Add('-U'); $psi.ArgumentList.Add($pgUser)
$psi.ArgumentList.Add('-Fc'); $psi.ArgumentList.Add('-Z'); $psi.ArgumentList.Add('6')
$psi.ArgumentList.Add('-d'); $psi.ArgumentList.Add($pgDb)
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false
$dump = [System.Diagnostics.Process]::Start($psi)

$psiAge = New-Object System.Diagnostics.ProcessStartInfo
$psiAge.FileName = 'age'
$psiAge.ArgumentList.Add('-r'); $psiAge.ArgumentList.Add($env:BACKUP_RECIPIENT)
$psiAge.ArgumentList.Add('-o'); $psiAge.ArgumentList.Add($file)
$psiAge.RedirectStandardInput = $true
$psiAge.UseShellExecute = $false
$ageProc = [System.Diagnostics.Process]::Start($psiAge)

$dump.StandardOutput.BaseStream.CopyTo($ageProc.StandardInput.BaseStream)
$ageProc.StandardInput.Close()
$dump.WaitForExit(); $ageProc.WaitForExit()
if ($dump.ExitCode -ne 0)    { throw "pg_dump falhou (exit $($dump.ExitCode))" }
if ($ageProc.ExitCode -ne 0) { throw "age falhou (exit $($ageProc.ExitCode))" }

# Checksum sobre o ciphertext.
$hash = (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLower()
"$hash  $(Split-Path -Leaf $file)" | Out-File -Encoding ascii -FilePath "$file.sha256"

# Rotate 30d.
Get-ChildItem -Path $BackupDir -File -Filter 'secblind-*' |
    Where-Object { $_.LastWriteTimeUtc -lt (Get-Date).ToUniversalTime().AddDays(-30) } |
    Remove-Item -Force

Write-Output "backup ok: $file"
