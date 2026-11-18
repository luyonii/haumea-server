// Harness for dynapi.cpp: PEB walk + EAT walk + hash convergence.
// Standalone console app; links dynapi.cpp directly (see .vcxproj).
// Output matches pe_loader_fuzzer style: "[PASS/FAIL] name (expected=X got=X)".

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include "dynapi.h"

#include <cstdio>
#include <cstdint>

using dynapi::hash_api;
using dynapi::hash_module;
using dynapi::hash_module_runtime;
using dynapi::resolve;
using dynapi::get_module;

// ---------------------------------------------------------------------------
// Test cases. Each returns true on pass, false on fail, and writes a one-line
// "expected=... got=..." description into `detail` (truncation-safe).
// ---------------------------------------------------------------------------

static bool t_hash_lowercase_convergence(char* detail, size_t cap) {
    // Case 1: compile-time hash_api of a known kernel32 export must resolve
    // to a non-null function pointer. Confirms hash_api (names, case-
    // sensitive) agrees with what the EAT walker computes at runtime.
    void* p = resolve(dynapi::modules::KERNEL32, hash_api("GetSystemTimeAsFileTime"));
    snprintf(detail, cap, "expected=non-null got=%p", p);
    return p != nullptr;
}

static bool t_hash_mixed_case_input(char* detail, size_t cap) {
    // hash_api is case-sensitive (header comment). Windows export names are
    // case-sensitive too: the EAT stores the exact spelling. So a lower-
    // cased name must NOT resolve, while the exact-case name must.
    void* ok  = resolve(dynapi::modules::KERNEL32, hash_api("GetSystemTimeAsFileTime"));
    void* bad = resolve(dynapi::modules::KERNEL32, hash_api("getsystemtimeasfiletime"));
    snprintf(detail, cap, "expected=(non-null,null) got=(%p,%p)", ok, bad);
    return ok != nullptr && bad == nullptr;
}

static bool t_module_not_present(char* detail, size_t cap) {
    void* p = get_module(hash_module("this-module-does-not-exist.dll"));
    snprintf(detail, cap, "expected=null got=%p", p);
    return p == nullptr;
}

static bool t_api_not_present(char* detail, size_t cap) {
    // 0xDEADBEEF is extremely unlikely to collide with any real FNV-1a of an
    // exported name; resolve() must iterate the whole EAT and return null.
    void* p = resolve(dynapi::modules::KERNEL32, 0xDEADBEEFu);
    snprintf(detail, cap, "expected=null got=%p", p);
    return p == nullptr;
}

static bool t_ldr_walk_terminates(char* detail, size_t cap) {
    // Repeated get_module calls must return the same non-null handle every
    // time; also implicitly checks the >256-step defensive cap doesn't hit.
    void* first = get_module(dynapi::modules::KERNEL32);
    if (!first) { snprintf(detail, cap, "expected=non-null got=null on first"); return false; }
    for (int i = 0; i < 1000; ++i) {
        void* p = get_module(dynapi::modules::KERNEL32);
        if (p != first) {
            snprintf(detail, cap, "expected=%p got=%p at iter %d", first, p, i);
            return false;
        }
    }
    snprintf(detail, cap, "expected=stable got=%p x1000", first);
    return true;
}

static bool t_eat_bounds_robustness(char* detail, size_t cap) {
    // After EAT-bounds fixes applied today, resolving many real ntdll/
    // kernel32 exports must still succeed. If any one fails, the bounds
    // check is too tight.
    struct { uint32_t mod; const char* name; } apis[] = {
        { dynapi::modules::NTDLL,    "NtQueryInformationProcess" },
        { dynapi::modules::NTDLL,    "NtQueryInformationThread"  },
        { dynapi::modules::NTDLL,    "NtClose"                   },
        { dynapi::modules::NTDLL,    "RtlAllocateHeap"           },
        { dynapi::modules::NTDLL,    "RtlFreeHeap"               },
        { dynapi::modules::NTDLL,    "NtProtectVirtualMemory"    },
        { dynapi::modules::NTDLL,    "NtAllocateVirtualMemory"   },
        { dynapi::modules::KERNEL32, "VirtualAlloc"              },
        { dynapi::modules::KERNEL32, "VirtualProtect"            },
        { dynapi::modules::KERNEL32, "GetProcAddress"            },
        { dynapi::modules::KERNEL32, "LoadLibraryA"              },
        { dynapi::modules::KERNEL32, "CreateFileA"               },
    };
    int total = static_cast<int>(sizeof(apis) / sizeof(*apis));
    int ok_count = 0;
    const char* first_miss = nullptr;
    for (auto& a : apis) {
        void* p = resolve(a.mod, hash_api(a.name));
        if (p) ++ok_count;
        else if (!first_miss) first_miss = a.name;
    }
    snprintf(detail, cap, "expected=%d/%d got=%d/%d miss=%s",
             total, total, ok_count, total, first_miss ? first_miss : "none");
    return ok_count == total;
}

// Case 7 (bonus): runtime module-hash function must converge with the
// constexpr hash. Checks the lower-casing + wide-char-high-byte simulation
// described in dynapi.h.
static bool t_module_hash_convergence(char* detail, size_t cap) {
    uint32_t rt1 = hash_module_runtime("kernel32.dll");
    uint32_t rt2 = hash_module_runtime("KERNEL32.DLL");
    uint32_t ct  = dynapi::modules::KERNEL32;
    snprintf(detail, cap, "expected=all-equal got=rt_lower=0x%08X rt_upper=0x%08X ct=0x%08X",
             rt1, rt2, ct);
    return rt1 == ct && rt2 == ct;
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

struct test_case {
    const char* name;
    bool (*run)(char* detail, size_t cap);
};

int main() {
    test_case cases[] = {
        { "hash_lowercase_convergence", &t_hash_lowercase_convergence },
        { "hash_mixed_case_input",      &t_hash_mixed_case_input      },
        { "module_not_present",         &t_module_not_present         },
        { "api_not_present",            &t_api_not_present            },
        { "ldr_walk_terminates",        &t_ldr_walk_terminates        },
        { "eat_bounds_robustness",      &t_eat_bounds_robustness      },
        { "module_hash_convergence",    &t_module_hash_convergence    },
    };

    const int total = static_cast<int>(sizeof(cases) / sizeof(*cases));
    int failures = 0;

    for (int i = 0; i < total; ++i) {
        char detail[256] = {0};
        bool pass = cases[i].run(detail, sizeof(detail));
        if (!pass) ++failures;
        printf("[%s] %s (%s)\n", pass ? "PASS" : "FAIL", cases[i].name, detail);
    }

    printf("\n%d/%d passed\n", total - failures, total);
    return failures;
}
