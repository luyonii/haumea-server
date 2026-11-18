// Minimal test harness for anti_tamper::text_section_crc32 / verify.
// Standalone console app; links the real anti_tamper.cpp and its deps.
//
// API operates only on the current process's own PE image (via __ImageBase),
// so section-mutation cases (NumberOfSections cap, SizeOfHeaders bounds) are
// NOT testable here without changing the API. Those malformed-PE paths are
// already covered by tests/pe_loader_fuzzer (which drives arbitrary byte
// buffers through pe_loader::map and exercises the same guards).

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include "anti_tamper.h"
#include "dynapi.h"

#include <cstdio>
#include <cstdint>

using sleep_fn = void (WINAPI*)(DWORD);

static void short_sleep() {
    // Resolve Sleep dynamically per project rule (no IAT entry for it here).
    auto fn = reinterpret_cast<sleep_fn>(
        dynapi::resolve(dynapi::modules::KERNEL32, API_HASH("Sleep")));
    if (fn) fn(10);
}

struct result { const char* name; bool pass; };

static result test_baseline_matches() {
    uint32_t baseline = anti_tamper::text_section_crc32();
    bool ok = (baseline != anti_tamper::SENTINEL_NOT_FOUND)
           && anti_tamper::verify(baseline);
    return {"baseline_matches", ok};
}

static result test_snapshot_idempotency() {
    uint32_t a = anti_tamper::text_section_crc32();
    uint32_t b = anti_tamper::text_section_crc32();
    bool ok = (a != anti_tamper::SENTINEL_NOT_FOUND) && (a == b);
    return {"snapshot_idempotency", ok};
}

static result test_verify_after_no_modification() {
    uint32_t baseline = anti_tamper::text_section_crc32();
    short_sleep();
    bool ok = (baseline != anti_tamper::SENTINEL_NOT_FOUND)
           && anti_tamper::verify(baseline);
    return {"verify_after_no_modification", ok};
}

// Sanity: verify() must reject a sentinel baseline (documents the contract,
// no modification of source needed).
static result test_sentinel_baseline_rejected() {
    bool ok = !anti_tamper::verify(anti_tamper::SENTINEL_NOT_FOUND);
    return {"sentinel_baseline_rejected", ok};
}

int main() {
    result cases[] = {
        test_baseline_matches(),
        test_snapshot_idempotency(),
        test_verify_after_no_modification(),
        test_sentinel_baseline_rejected(),
    };

    int total = static_cast<int>(sizeof(cases) / sizeof(*cases));
    int failures = 0;
    for (int i = 0; i < total; ++i) {
        printf("[%s] %s\n", cases[i].pass ? "PASS" : "FAIL", cases[i].name);
        if (!cases[i].pass) ++failures;
    }
    printf("\n%d/%d passed\n", total - failures, total);
    return failures;
}
