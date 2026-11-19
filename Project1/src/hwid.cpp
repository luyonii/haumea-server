#include "hwid.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <winioctl.h>
#include <intrin.h>
#include <memory>
#include <cstring>

namespace hwid {

// ---- function pointer typedefs (resolved at runtime via dynapi) ----------

using fn_CreateFileA = HANDLE(WINAPI*)(
    LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using fn_DeviceIoControl = BOOL(WINAPI*)(
    HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
using fn_CloseHandle = BOOL(WINAPI*)(HANDLE);
using fn_GetSystemFirmwareTable = UINT(WINAPI*)(DWORD, DWORD, PVOID, DWORD);

using fn_BCryptOpenAlgorithmProvider = long(WINAPI*)(
    void**, const wchar_t*, const wchar_t*, ULONG);
using fn_BCryptCreateHash = long(WINAPI*)(
    void*, void**, uint8_t*, ULONG, uint8_t*, ULONG, ULONG);
using fn_BCryptHashData     = long(WINAPI*)(void*, uint8_t*, ULONG, ULONG);
using fn_BCryptFinishHash   = long(WINAPI*)(void*, uint8_t*, ULONG, ULONG);
using fn_BCryptDestroyHash  = long(WINAPI*)(void*);
using fn_BCryptCloseAlgProv = long(WINAPI*)(void*, ULONG);

// ---- NVMe / SATA disk serial via IOCTL_STORAGE_QUERY_PROPERTY -----------

struct disk_serial { uint8_t data[256]; uint32_t len; };

static bool collect_disk_serial(disk_serial& out) {
    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    if (!k32) return false;

    auto pCreateFile = reinterpret_cast<fn_CreateFileA>(
        dynapi::resolve(k32, API_HASH("CreateFileA")));
    auto pIoctl = reinterpret_cast<fn_DeviceIoControl>(
        dynapi::resolve(k32, API_HASH("DeviceIoControl")));
    auto pClose = reinterpret_cast<fn_CloseHandle>(
        dynapi::resolve(k32, API_HASH("CloseHandle")));
    if (!pCreateFile || !pIoctl || !pClose) return false;

    HANDLE drive = pCreateFile(
        OBF("\\\\.\\PhysicalDrive0"),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (drive == INVALID_HANDLE_VALUE) return false;

    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType  = PropertyStandardQuery;

    uint8_t buf[4096]{};
    DWORD   returned = 0;

    BOOL ok = pIoctl(drive, IOCTL_STORAGE_QUERY_PROPERTY,
                     &query, sizeof(query), buf, sizeof(buf), &returned, nullptr);
    pClose(drive);
    if (!ok) return false;

    auto desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf);
    if (desc->SerialNumberOffset == 0 || desc->SerialNumberOffset >= returned)
        return false;

    auto serial = reinterpret_cast<const char*>(buf + desc->SerialNumberOffset);
    size_t slen = strnlen(serial, sizeof(buf) - desc->SerialNumberOffset);
    if (slen == 0 || slen > sizeof(out.data)) return false;

    memcpy(out.data, serial, slen);
    out.len = static_cast<uint32_t>(slen);
    return true;
}

// ---- SMBIOS UUID (Type 1 — System Information, offset 8) ----------------

static bool collect_smbios_uuid(uint8_t uuid[16]) {
    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    if (!k32) return false;

    auto pGetFW = reinterpret_cast<fn_GetSystemFirmwareTable>(
        dynapi::resolve(k32, API_HASH("GetSystemFirmwareTable")));
    if (!pGetFW) return false;

    constexpr DWORD RSMB = 'RSMB';
    UINT size = pGetFW(RSMB, 0, nullptr, 0);
    if (size == 0) return false;

    auto buffer = std::make_unique<uint8_t[]>(size);
    if (pGetFW(RSMB, 0, buffer.get(), size) != size) return false;

    // Skip 8-byte RawSMBIOSData header, walk structures
    uint8_t* data = buffer.get() + 8;
    uint8_t* end  = buffer.get() + size;

    while (data + 4 < end) {
        uint8_t type   = data[0];
        uint8_t length = data[1];

        if (type == 1 && length >= 25) {
            memcpy(uuid, data + 8, 16);
            return true;
        }

        // Skip formatted area
        data += length;
        // Skip unformatted string area (double-null terminated)
        while (data + 1 < end && !(data[0] == 0 && data[1] == 0))
            ++data;
        data += 2;
    }
    return false;
}

// ---- CPUID (vendor + model/stepping + extended features) ----------------

struct cpuid_block { int regs[12]; };   // 3 leaves x 4 registers

static void collect_cpuid(cpuid_block& out) {
    __cpuid(out.regs + 0, 0);          // leaf 0: vendor
    __cpuid(out.regs + 4, 1);          // leaf 1: model / stepping / features
    __cpuid(out.regs + 8, 0x80000001); // extended features

    // leaf 1 EBX[31:24] is the Initial APIC ID: it reports the logical CPU the
    // thread happens to run on, so it changes run to run and broke HWID stability.
    out.regs[5] &= 0x00FFFFFF;
}

// ---- SHA-256 via Windows CNG (bcrypt.dll, loaded dynamically) -----------

static std::string sha256_hex(const uint8_t* data, size_t len) {
    auto bcrypt_mod = dynapi::load_module(OBF("bcrypt.dll"));
    if (!bcrypt_mod) return {};

    auto pOpen   = reinterpret_cast<fn_BCryptOpenAlgorithmProvider>(
        dynapi::resolve(bcrypt_mod, API_HASH("BCryptOpenAlgorithmProvider")));
    auto pCreate = reinterpret_cast<fn_BCryptCreateHash>(
        dynapi::resolve(bcrypt_mod, API_HASH("BCryptCreateHash")));
    auto pHash   = reinterpret_cast<fn_BCryptHashData>(
        dynapi::resolve(bcrypt_mod, API_HASH("BCryptHashData")));
    auto pFinish = reinterpret_cast<fn_BCryptFinishHash>(
        dynapi::resolve(bcrypt_mod, API_HASH("BCryptFinishHash")));
    auto pDestroyH = reinterpret_cast<fn_BCryptDestroyHash>(
        dynapi::resolve(bcrypt_mod, API_HASH("BCryptDestroyHash")));
    auto pCloseAlg = reinterpret_cast<fn_BCryptCloseAlgProv>(
        dynapi::resolve(bcrypt_mod, API_HASH("BCryptCloseAlgorithmProvider")));

    if (!pOpen || !pCreate || !pHash || !pFinish || !pDestroyH || !pCloseAlg)
        return {};

    // Build the algorithm name on the stack from OBF narrow string (avoids L"SHA256" in .rdata)
    auto narrow = OBF("SHA256");
    wchar_t alg_id[7]{};
    for (int i = 0; i < 7; ++i)
        alg_id[i] = static_cast<wchar_t>(static_cast<uint8_t>(narrow.c_str()[i]));

    void* alg = nullptr;
    if (pOpen(&alg, alg_id, nullptr, 0) != 0) return {};

    void* hash_handle = nullptr;
    if (pCreate(alg, &hash_handle, nullptr, 0, nullptr, 0, 0) != 0) {
        pCloseAlg(alg, 0);
        return {};
    }

    long status = pHash(hash_handle,
                        const_cast<uint8_t*>(data),
                        static_cast<ULONG>(len), 0);
    if (status != 0) {
        pDestroyH(hash_handle);
        pCloseAlg(alg, 0);
        return {};
    }

    uint8_t digest[32]{};
    status = pFinish(hash_handle, digest, 32, 0);
    pDestroyH(hash_handle);
    pCloseAlg(alg, 0);

    // Zero the widened algorithm name
    volatile wchar_t* wp = alg_id;
    for (int i = 0; i < 7; ++i) wp[i] = 0;

    if (status != 0) return {};

    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (uint8_t b : digest) {
        result += hex[b >> 4];
        result += hex[b & 0x0F];
    }

    // Zero the raw digest
    volatile uint8_t* dp = digest;
    for (int i = 0; i < 32; ++i) dp[i] = 0;

    return result;
}

// ---- Public API ---------------------------------------------------------

std::string generate() {
    disk_serial ds{};
    uint8_t     smbios_uuid[16]{};
    cpuid_block cpu{};

    bool has_disk = collect_disk_serial(ds);
    bool has_uuid = collect_smbios_uuid(smbios_uuid);
    collect_cpuid(cpu);

    // At least CPUID is always available; disk/SMBIOS may fail without elevation
    if (!has_disk && !has_uuid) {
        // CPUID alone is weak but still usable — proceed
    }

    // Concatenate: [disk_serial_len:4][disk_serial][smbios_uuid:16][cpuid:48]
    size_t total = 4 + ds.len + 16 + sizeof(cpu.regs);
    auto buf = std::make_unique<uint8_t[]>(total);
    size_t off = 0;

    memcpy(buf.get() + off, &ds.len, 4); off += 4;
    if (ds.len > 0) { memcpy(buf.get() + off, ds.data, ds.len); off += ds.len; }
    memcpy(buf.get() + off, smbios_uuid, 16); off += 16;
    memcpy(buf.get() + off, cpu.regs, sizeof(cpu.regs)); off += sizeof(cpu.regs);

    auto result = sha256_hex(buf.get(), off);

    // Scrub temporaries
    volatile uint8_t* p = buf.get();
    for (size_t i = 0; i < total; ++i) p[i] = 0;
    volatile uint8_t* sp = reinterpret_cast<volatile uint8_t*>(&ds);
    for (size_t i = 0; i < sizeof(ds); ++i) sp[i] = 0;
    volatile uint8_t* up = smbios_uuid;
    for (size_t i = 0; i < 16; ++i) up[i] = 0;

    return result;
}

} // namespace hwid
