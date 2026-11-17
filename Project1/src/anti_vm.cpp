#include "anti_vm.h"
#include "dynapi.h"
#include "obfstr.h"

#include <Windows.h>
#include <intrin.h>

// Hand-declared minimal IP_ADAPTER_ADDRESSES subset — avoids winsock2/iphlpapi
// which carry #pragma comment(lib,...) directives.
#ifndef AF_UNSPEC
#define AF_UNSPEC 0
#endif
#ifndef NO_ERROR
#define NO_ERROR 0
#endif
#ifndef ERROR_BUFFER_OVERFLOW
#define ERROR_BUFFER_OVERFLOW 111
#endif

typedef struct _SOCKET_ADDRESS_LITE {
    void*  lpSockaddr;
    int    iSockaddrLength;
} SOCKET_ADDRESS_LITE;

typedef struct _IP_ADAPTER_ADDRESSES_LH_LITE {
    union { uint64_t Alignment; struct { uint32_t Length; uint32_t IfIndex; }; };
    struct _IP_ADAPTER_ADDRESSES_LH_LITE* Next;
    void*    AdapterName;
    void*    FirstUnicastAddress;
    void*    FirstAnycastAddress;
    void*    FirstMulticastAddress;
    void*    FirstDnsServerAddress;
    wchar_t* DnsSuffix;
    wchar_t* Description;
    wchar_t* FriendlyName;
    uint8_t  PhysicalAddress[8];
    uint32_t PhysicalAddressLength;
    // Trailing fields we don't use — pad conservatively.
    uint8_t  _tail[512];
} IP_ADAPTER_ADDRESSES_LITE;

namespace anti_vm {

// ---- GetAdaptersAddresses prototype (iphlpapi) ----
using NETIO_STATUS = ULONG;
using fn_GetAdaptersAddresses = NETIO_STATUS(WINAPI*)(
    ULONG Family, ULONG Flags, PVOID Reserved,
    IP_ADAPTER_ADDRESSES_LITE* AdapterAddresses, PULONG SizePointer);

// ---- advapi32 reg prototypes ----
using fn_RegOpenKeyExA = LONG(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
using fn_RegCloseKey   = LONG(WINAPI*)(HKEY);

// ---- kernel32 heap prototypes ----
using fn_GetProcessHeap = HANDLE(WINAPI*)();
using fn_HeapAlloc      = LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T);
using fn_HeapFree       = BOOL(WINAPI*)(HANDLE, DWORD, LPVOID);

static bool match_mac(const uint8_t* m) {
    // VMware
    if (m[0]==0x00 && m[1]==0x05 && m[2]==0x69) return true;
    if (m[0]==0x00 && m[1]==0x0C && m[2]==0x29) return true;
    if (m[0]==0x00 && m[1]==0x1C && m[2]==0x14) return true;
    if (m[0]==0x00 && m[1]==0x50 && m[2]==0x56) return true;
    // VirtualBox
    if (m[0]==0x08 && m[1]==0x00 && m[2]==0x27) return true;
    // Hyper-V
    if (m[0]==0x00 && m[1]==0x15 && m[2]==0x5D) return true;
    return false;
}

static bool check_hypervisor_bit() {
    int info[4]{};
    __cpuid(info, 1);
    return (info[2] & (1 << 31)) != 0;
}

static bool check_hv_vendor() {
    int info[4]{};
    __cpuid(info, 0x40000000);
    char vendor[13]{};
    *reinterpret_cast<int*>(&vendor[0]) = info[1];
    *reinterpret_cast<int*>(&vendor[4]) = info[2];
    *reinterpret_cast<int*>(&vendor[8]) = info[3];

    auto match = [&](const char* needle) {
        for (int i = 0; i < 12; ++i)
            if (vendor[i] != needle[i]) return false;
        return true;
    };

    auto v1 = OBF("KVMKVMKVM\0\0\0");
    auto v2 = OBF("Microsoft Hv");
    auto v3 = OBF("VMwareVMware");
    auto v4 = OBF("XenVMMXenVMM");
    auto v5 = OBF("VBoxVBoxVBox");
    return match(v1.c_str()) || match(v2.c_str()) || match(v3.c_str())
        || match(v4.c_str()) || match(v5.c_str());
}

static bool check_rdtsc() {
    // 9 samples, median; CPUID brackets the window as a serializing fence.
    uint64_t deltas[9]{};
    for (int i = 0; i < 9; ++i) {
        int tmp[4];
        __cpuid(tmp, 0);             // serialize + flush OOO
        uint64_t t0 = __rdtsc();
        __cpuid(tmp, 0);
        uint64_t t1 = __rdtsc();
        deltas[i] = t1 - t0;
    }
    // bubble sort tiny array
    for (int i = 0; i < 9; ++i)
        for (int j = i + 1; j < 9; ++j)
            if (deltas[j] < deltas[i]) {
                auto t = deltas[i]; deltas[i] = deltas[j]; deltas[j] = t;
            }
    // shortcut: fixed 50000-cycle threshold, upgrade when TSC calibration added
    return deltas[4] > 50000;
}

static bool check_mac() {
    auto iphlp = dynapi::load_module(OBF("iphlpapi.dll").c_str());
    if (!iphlp) return false;
    auto pGAA = reinterpret_cast<fn_GetAdaptersAddresses>(
        dynapi::resolve(iphlp, API_HASH("GetAdaptersAddresses")));
    if (!pGAA) return false;

    auto k32 = dynapi::get_module(dynapi::modules::KERNEL32);
    auto pGPH = reinterpret_cast<fn_GetProcessHeap>(
        dynapi::resolve(k32, API_HASH("GetProcessHeap")));
    auto pHA = reinterpret_cast<fn_HeapAlloc>(
        dynapi::resolve(k32, API_HASH("HeapAlloc")));
    auto pHF = reinterpret_cast<fn_HeapFree>(
        dynapi::resolve(k32, API_HASH("HeapFree")));
    if (!pGPH || !pHA || !pHF) return false;
    HANDLE heap = pGPH();
    if (!heap) return false;

    // MS recommends 15 KB initial; grow on ERROR_BUFFER_OVERFLOW up to 2 MB.
    ULONG sz = 15 * 1024;
    const ULONG cap = 2 * 1024 * 1024;
    uint8_t* buf = static_cast<uint8_t*>(pHA(heap, 0, sz));
    if (!buf) return false;

    NETIO_STATUS st = ERROR_BUFFER_OVERFLOW;
    for (int tries = 0; tries < 3; ++tries) {
        st = pGAA(AF_UNSPEC, 0, nullptr,
                  reinterpret_cast<IP_ADAPTER_ADDRESSES_LITE*>(buf), &sz);
        if (st != ERROR_BUFFER_OVERFLOW) break;
        pHF(heap, 0, buf);
        // sz now holds the required size from the call; also enforce doubling cap.
        ULONG next = sz > (15u * 1024u) ? sz : (15u * 1024u * 2u);
        if (next > cap) next = cap;
        sz = next;
        buf = static_cast<uint8_t*>(pHA(heap, 0, sz));
        if (!buf) return false;
    }
    if (st != NO_ERROR) {
        pHF(heap, 0, buf);
        return false;
    }

    bool found = false;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES_LITE*>(buf); a; a = a->Next) {
        if (a->PhysicalAddressLength >= 3 && match_mac(a->PhysicalAddress)) {
            found = true;
            break;
        }
    }
    pHF(heap, 0, buf);
    return found;
}

static bool check_registry() {
    auto advapi = dynapi::get_module(dynapi::modules::ADVAPI32);
    if (!advapi) advapi = dynapi::load_module(OBF("advapi32.dll").c_str());
    if (!advapi) return false;

    auto pOpen  = reinterpret_cast<fn_RegOpenKeyExA>(
        dynapi::resolve(advapi, API_HASH("RegOpenKeyExA")));
    auto pClose = reinterpret_cast<fn_RegCloseKey>(
        dynapi::resolve(advapi, API_HASH("RegCloseKey")));
    if (!pOpen || !pClose) return false;

    auto k1 = OBF("SOFTWARE\\Oracle\\VirtualBox Guest Additions");
    auto k2 = OBF("SOFTWARE\\VMware, Inc.\\VMware Tools");
    HKEY h = nullptr;
    if (pOpen(HKEY_LOCAL_MACHINE, k1.c_str(), 0, KEY_READ, &h) == ERROR_SUCCESS) {
        pClose(h);
        return true;
    }
    if (pOpen(HKEY_LOCAL_MACHINE, k2.c_str(), 0, KEY_READ, &h) == ERROR_SUCCESS) {
        pClose(h);
        return true;
    }
    return false;
}

uint32_t check_all() {
    uint32_t mask = 0;
    if (check_hypervisor_bit()) mask |= static_cast<uint32_t>(detection::hypervisor_bit);
    if (check_hv_vendor())      mask |= static_cast<uint32_t>(detection::hv_vendor);
    if (check_rdtsc())          mask |= static_cast<uint32_t>(detection::rdtsc_timing);
    if (check_mac())            mask |= static_cast<uint32_t>(detection::vm_mac_prefix);
    if (check_registry())       mask |= static_cast<uint32_t>(detection::vm_registry);
    return mask;
}

} // namespace anti_vm
