# scripts/extract_blob.ps1 — pulls the .text section bytes out of a COFF
# object file, resolves intra-section REL32 relocations in place, and
# writes the result as a raw position-independent blob.
#
# Any relocation that targets a symbol OUTSIDE the .text$mn (CRT helpers
# like _memcpy, __allshl, __aulldiv, or external DLL names) aborts the
# build: the worker is meant to call only its own static helpers plus
# pointer-valued APIs passed through sb_worker_args.
#
# Invoked from the Project1 BuildStubWorkerBlob MSBuild target after
# cl.exe emits stub_worker.obj.
#
# Usage:
#   extract_blob.ps1 -Obj build\stub_worker.obj -Out build\stub_worker.bin

param(
    [Parameter(Mandatory)][string] $Obj,
    [Parameter(Mandatory)][string] $Out
)

$ErrorActionPreference = 'Stop'

function Die($msg) { Write-Host "extract_blob: $msg" -ForegroundColor Red; exit 2 }

if (-not (Test-Path -LiteralPath $Obj)) { Die "input not found: $Obj" }
$bytes = [System.IO.File]::ReadAllBytes($Obj)
if ($bytes.Length -lt 20)              { Die "file too small for a COFF header ($($bytes.Length) bytes)" }

# IMAGE_FILE_HEADER (20 bytes).
$machine   = [System.BitConverter]::ToUInt16($bytes, 0)
$nSec      = [System.BitConverter]::ToUInt16($bytes, 2)
$symTabOff = [System.BitConverter]::ToUInt32($bytes, 8)
$nSyms     = [System.BitConverter]::ToUInt32($bytes, 12)
$optHdr    = [System.BitConverter]::ToUInt16($bytes, 16)

if ($machine -ne 0x14C) { Die ('unexpected machine 0x{0:X} (want 0x14C / i386)' -f $machine) }

# ---- Walk sections to find the single .text* code section ----
$sectionOff   = 20 + $optHdr
$textIdx      = $null   # 1-based COFF section index
$textStart    = $null
$textSize     = 0
$textRelocOff = 0
$textNReloc   = 0
$textName     = ''

for ($i = 0; $i -lt $nSec; ++$i) {
    $off = $sectionOff + ($i * 40)
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $off, 8).TrimEnd([char]0)
    $sizeRaw  = [System.BitConverter]::ToUInt32($bytes, $off + 16)
    $ptrRaw   = [System.BitConverter]::ToUInt32($bytes, $off + 20)
    $ptrReloc = [System.BitConverter]::ToUInt32($bytes, $off + 24)
    $numReloc = [System.BitConverter]::ToUInt16($bytes, $off + 32)

    if ($name -eq '.text' -or $name.StartsWith('.text$')) {
        if ($textStart -ne $null) {
            Die "multiple code sections ($textName + $name); compile with /Gy- to merge."
        }
        $textIdx      = $i + 1
        $textStart    = $ptrRaw
        $textSize     = $sizeRaw
        $textRelocOff = $ptrReloc
        $textNReloc   = $numReloc
        $textName     = $name
    }
}

if ($null -eq $textStart) { Die 'no .text section found.' }
if ($textSize -eq 0 -or ($textStart + $textSize) -gt $bytes.Length) {
    Die ("{0} offsets out of range (start={1}, size={2}, file={3})." -f $textName, $textStart, $textSize, $bytes.Length)
}

# ---- Read the COFF symbol table (needed to resolve relocs) ----
# Each primary symbol is 18 bytes:
#   0..7   Name (short) OR 0,0,0,0 + offset-into-string-table (4+4)
#   8..11  Value         (section offset for a defined function)
#   12..13 SectionNumber (1-based; 0=UNDEF, -1=ABS, -2=DEBUG)
#   14..15 Type
#   16     StorageClass
#   17     NumberOfAuxSymbols
$strTabOff = $symTabOff + ($nSyms * 18)

function Read-SymName([int]$symOff) {
    $first4 = [System.BitConverter]::ToUInt32($bytes, $symOff)
    if ($first4 -eq 0) {
        $strOff = [System.BitConverter]::ToUInt32($bytes, $symOff + 4)
        $abs    = $strTabOff + $strOff
        $end    = $abs
        while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
        return [System.Text.Encoding]::ASCII.GetString($bytes, $abs, $end - $abs)
    }
    $raw = [System.Text.Encoding]::ASCII.GetString($bytes, $symOff, 8)
    return $raw.TrimEnd([char]0)
}

# Build symbol-index map so reloc lookups are O(1). Keys are COFF
# symbol indices (primary entries only; aux slots skipped but still
# index-incremented), values are hashtables with .Name, .Value,
# .Section.
$syms = @{}
$s = 0
while ($s -lt $nSyms) {
    $off     = $symTabOff + ($s * 18)
    $name    = Read-SymName $off
    $value   = [System.BitConverter]::ToUInt32($bytes, $off + 8)
    $section = [System.BitConverter]::ToInt16($bytes, $off + 12)
    $naux    = [int]$bytes[$off + 17]
    $syms[$s] = @{ Name = $name; Value = $value; Section = $section }
    $s += 1 + $naux
}

# ---- Walk text relocations ----
# Each entry: VirtualAddress (4) + SymbolTableIndex (4) + Type (2) = 10 bytes.
$IMAGE_REL_I386_DIR32  = 0x0006
$IMAGE_REL_I386_REL32  = 0x0014

$external = @()
$blob = New-Object byte[] $textSize
[System.Array]::Copy($bytes, $textStart, $blob, 0, $textSize)

for ($r = 0; $r -lt $textNReloc; ++$r) {
    $rOff = $textRelocOff + ($r * 10)
    $va   = [System.BitConverter]::ToUInt32($bytes, $rOff)
    $idx  = [System.BitConverter]::ToUInt32($bytes, $rOff + 4)
    $type = [System.BitConverter]::ToUInt16($bytes, $rOff + 8)

    if (-not $syms.ContainsKey([int]$idx)) {
        Die ("reloc #{0} references unknown symbol index {1}" -f $r, $idx)
    }
    $sym = $syms[[int]$idx]

    if ($sym.Section -ne $textIdx) {
        # External reloc. Record and fail at end with the full list.
        $external += "offset=0x{0:X} type=0x{1:X} symbol={2}" -f $va, $type, $sym.Name
        continue
    }

    if ($type -eq $IMAGE_REL_I386_REL32) {
        # 32-bit PC-relative. Final = target - (site + 4) + addend.
        $addend = [System.BitConverter]::ToInt32($blob, $va)
        $delta  = [int64]$sym.Value - ([int64]$va + 4) + [int64]$addend
        $patch  = [System.BitConverter]::GetBytes([int32]$delta)
        [System.Array]::Copy($patch, 0, $blob, $va, 4)
    }
    elseif ($type -eq $IMAGE_REL_I386_DIR32) {
        # Absolute 32-bit address. Not position-independent even if the
        # target is in .text — the blob's base is unknown at build time.
        $external += "offset=0x{0:X} type=DIR32 symbol={1} (absolute address in code)" -f $va, $sym.Name
    }
    else {
        $external += "offset=0x{0:X} unsupported type=0x{1:X} symbol={2}" -f $va, $type, $sym.Name
    }
}

if ($external.Count -gt 0) {
    Write-Host "extract_blob: $textName has $($external.Count) unresolved relocation(s):" -ForegroundColor Red
    foreach ($e in $external) { Write-Host "  $e" -ForegroundColor Red }
    Write-Host 'Remove external calls (CRT helpers, imports) from stub_worker.c, or route them through sb_worker_args pointers.' -ForegroundColor Yellow
    exit 2
}

$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}
[System.IO.File]::WriteAllBytes($Out, $blob)

Write-Host ("extract_blob: wrote {0} bytes ({1}, {2} relocs resolved) to {3}" `
             -f $blob.Length, $textName, $textNReloc, $Out)
exit 0
