# Apply schema (idempotent-ish: errors if tables exist), insert a test
# license, and load dummy_payload\payload.dll into payload_builds.
# Requires the postgres container from docker-compose.yml to be up.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here      = Split-Path -Parent $MyInvocation.MyCommand.Path
$intRoot   = Split-Path -Parent $here
$projRoot  = Split-Path -Parent $intRoot
$migration = Join-Path $projRoot 'server\migrations\0001_init.sql'
$payload   = Join-Path $intRoot  'dummy_payload\payload.dll'

if (-not (Test-Path $payload)) {
    throw "payload.dll not found at $payload. Run scripts\build_dummy_payload.ps1 first."
}

$license = 'TEST-' + (-join ((1..4) | ForEach-Object {
    -join ((1..4) | ForEach-Object { '{0:X}' -f (Get-Random -Max 16) })
}) -join '-')

# Pipe schema into psql inside the container.
Write-Host "Applying schema..."
Get-Content -Raw $migration | docker compose -f (Join-Path $intRoot 'docker-compose.yml') exec -T postgres psql -U secblind -d secblind

# Insert license.
Write-Host "Inserting license: $license"
$sql = "INSERT INTO licenses (license_key) VALUES ('$license') ON CONFLICT (license_key) DO NOTHING;"
$sql | docker compose -f (Join-Path $intRoot 'docker-compose.yml') exec -T postgres psql -U secblind -d secblind

# Copy PE into container and INSERT with pg_read_binary_file.
Write-Host "Uploading payload.dll..."
docker compose -f (Join-Path $intRoot 'docker-compose.yml') cp $payload postgres:/tmp/payload.dll
$sql2 = @"
INSERT INTO payload_builds (license_id, pe_bytes)
VALUES (
  (SELECT id FROM licenses WHERE license_key='$license'),
  pg_read_binary_file('/tmp/payload.dll')
);
"@
$sql2 | docker compose -f (Join-Path $intRoot 'docker-compose.yml') exec -T postgres psql -U secblind -d secblind

Write-Host ""
Write-Host "License seeded: $license"
Write-Host "Set this string in the loader (hard-coded or runtime prompt -- see auth.cpp)."
