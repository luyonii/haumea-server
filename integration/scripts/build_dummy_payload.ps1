# Build dummy_payload\payload.dll as x64 MSVC DLL. Self-sufficient: locates
# vcvarsall.bat via vswhere and invokes the x64 toolchain in a cmd subshell.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pDir = Join-Path (Split-Path -Parent $here) 'dummy_payload'
$dll  = Join-Path $pDir 'payload.dll'

$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found at $vswhere" }

$vsInstall = & $vswhere -latest -prerelease -products '*' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vsInstall) { throw "No VS installation with VC x64 tools found." }

$vcvars = Join-Path $vsInstall 'VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path $vcvars)) { throw "vcvarsall.bat not found at $vcvars" }

Push-Location $pDir
try {
    Remove-Item -Force payload.dll,payload.obj,payload.exp,payload.lib -ErrorAction SilentlyContinue
    $cmd = "`"$vcvars`" x64 && cl.exe /nologo /LD /O2 /W3 payload.c user32.lib /link /OUT:payload.dll"
    & cmd.exe /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "cl failed with exit $LASTEXITCODE" }
    Remove-Item -Force payload.obj,payload.exp,payload.lib -ErrorAction SilentlyContinue
}
finally { Pop-Location }

if (-not (Test-Path $dll)) { throw "Build produced no $dll" }

# Verify Machine == 0x8664 (IMAGE_FILE_MACHINE_AMD64)
$bytes = [System.IO.File]::ReadAllBytes($dll)
if ($bytes.Length -lt 0x40) { throw "DLL too small." }
$e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
if ($bytes.Length -lt $e_lfanew + 6) { throw "DLL truncated." }
$machine = [BitConverter]::ToUInt16($bytes, $e_lfanew + 4)
$machineHex = '0x{0:X4}' -f $machine
if ($machine -ne 0x8664) {
    throw "DLL Machine=$machineHex, expected 0x8664 (AMD64). Build is not x64."
}
Write-Host "Built x64 DLL: $dll (Machine=$machineHex)"
