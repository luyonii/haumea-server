#pragma once
// Custom in-memory PE module loader (used by commercial DRM SDKs to run an
// entitled module without writing it to disk). All Windows APIs are bound
// at runtime through the symbol resolver.

#include <cstdint>
#include <cstddef>

namespace pe_loader {

struct mapped_image {
    void*  base        = nullptr;  // VirtualAlloc'd region
    size_t size        = 0;
    void*  entry_point = nullptr;  // AddressOfEntryPoint + base
};

enum class map_error {
    ok,
    bad_dos_header,
    bad_nt_header,
    bad_machine,       // not AMD64
    alloc_failed,
    section_copy_failed,
    reloc_failed,
    import_failed,
    protect_failed,
};

// Maps a PE image from its in-memory bytes.
// On success: sections copied, relocations applied, imports resolved via dynapi,
// page protections set, DOS+NT headers zeroed (anti-dump).
map_error map(const uint8_t* pe_bytes, size_t pe_size, mapped_image& out);

// Executes the mapped image's entry point. For a DLL, calls with
// (base, DLL_PROCESS_ATTACH, nullptr). For an EXE, calls the entry directly.
bool execute(const mapped_image& img, bool is_dll);

// Frees the mapped region via VirtualFree(MEM_RELEASE), zeros memory first.
void unmap(mapped_image& img);

} // namespace pe_loader
