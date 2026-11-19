#pragma once
// Device fingerprint id: NVMe serial + SMBIOS UUID + CPUID -> SHA-256 via
// Windows CNG. Used to bind an activation code to one machine.

#include <cstdint>
#include <string>

namespace hwid {

// Collect hardware identifiers and return SHA-256 as 64-char lowercase hex.
// Returns empty string on total failure; partial data still produces a valid hash.
std::string generate();

} // namespace hwid
