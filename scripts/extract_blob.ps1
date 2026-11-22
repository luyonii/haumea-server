# build/extract_blob.ps1 — pulls the .text section bytes out of a COFF
# object file and writes them raw to disk, after asserting that .text has
# no relocations (otherwise the extracted blob is not position-independent
# and would corrupt the target process once copied in by the loader).
#
# Invoked from the Project1 PreBuildEvent, which runs it after cl.exe has
# emitted stub_worker.obj.
#
# Usage:
#   extract_blob.ps1 -Obj build\stub_worker.obj -Out build\stub_worker.bin

param(
    [Parameter(Mandatory)][string] $Obj,
    [Parameter(Mandatory)][string] $Out
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Obj)) {
    Write-Host "extract_blob: input not found: $Obj" -ForegroundColor Red
    exit 2
}

$bytes = [System.IO.File]::ReadAllBytes($Obj)

if ($bytes.Length -lt 20) {
    Write-Host "extract_blob: file too small for a COFF header ($($bytes.Length) bytes)" -ForegroundColor Red
    exit 2
}

# IMAGE_FILE_HEADER layout (20 bytes):
#   0..1   Machine
#   2..3   NumberOfSections
#   4..7   TimeDateStamp
#   8..11  PointerToSymbolTable
#   12..15 NumberOfSymbols
#   16..17 SizeOfOptionalHeader
#   18..19 Characteristics
$machine = [System.BitConverter]::ToUInt16($bytes, 0)
$nSec    = [System.BitConverter]::ToUInt16($bytes, 2)
$optHdr  = [System.BitConverter]::ToUInt16($bytes, 16)

# 0x14C = IMAGE_FILE_MACHINE_I386. Milestones are x86-only for now; abort
# loudly if someone retargets this without updating the stub.
if ($machine -ne 0x14C) {
    Write-Host ('extract_blob: unexpected machine 0x{0:X} (want 0x14C / i386)' -f $machine) -ForegroundColor Red
    exit 2
}

$sectionOff = 20 + $optHdr
$textStart  = $null
$textSize   = 0
$textReloc  = 0
$textName   = ''

for ($i = 0; $i -lt $nSec; ++$i) {
    $off = $sectionOff + ($i * 40)
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $off, 8)
    # COFF names are NUL-padded to 8 bytes; trim trailing NULs for the compare.
    $name = $name.TrimEnd([char]0)

    $sizeRaw  = [System.BitConverter]::ToUInt32($bytes, $off + 16)
    $ptrRaw   = [System.BitConverter]::ToUInt32($bytes, $off + 20)
    $numReloc = [System.BitConverter]::ToUInt16($bytes, $off + 32)

    # `.text`, `.text$mn`, `.text$x` are all code sections cl.exe can emit.
    if ($name -eq '.text' -or $name.StartsWith('.text$')) {
        if ($textStart -ne $null) {
            Write-Host "extract_blob: multiple code sections ($textName + $name); blob layout ambiguous." -ForegroundColor Red
            exit 2
        }
        $textStart = $ptrRaw
        $textSize  = $sizeRaw
        $textReloc = $numReloc
        $textName  = $name
    }
}

if ($null -eq $textStart) {
    Write-Host 'extract_blob: no .text section found.' -ForegroundColor Red
    exit 2
}

if ($textReloc -ne 0) {
    Write-Host ("extract_blob: {0} has {1} relocations; blob is not position-independent." -f $textName, $textReloc) -ForegroundColor Red
    Write-Host 'Remove string literals, globals, and switch-table statics from stub_worker.c.' -ForegroundColor Yellow
    exit 2
}

if ($textSize -eq 0 -or ($textStart + $textSize) -gt $bytes.Length) {
    Write-Host ("extract_blob: {0} offsets out of range (start={1}, size={2}, file={3})." -f $textName, $textStart, $textSize, $bytes.Length) -ForegroundColor Red
    exit 2
}

$blob = New-Object byte[] $textSize
[System.Array]::Copy($bytes, $textStart, $blob, 0, $textSize)

$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}
[System.IO.File]::WriteAllBytes($Out, $blob)

Write-Host ("extract_blob: wrote {0} bytes ({1}) to {2}" -f $blob.Length, $textName, $Out)
exit 0
