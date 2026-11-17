#pragma once
// Thin authenticated RPC client. Wraps net::post with an HMAC envelope.

#include <string>
#include <cstdint>

namespace rpc {

struct response {
    bool success = false;
    int  status_code = 0;
    std::string body;
    std::string error;
};

// POST /api/v1/rpc/call with:
//   {"method":..,"session_token":..,"payload":<params_json>,"timestamp":..,"hmac":..}
// session_key here MUST be the k_rpc sub-key (HKDF-Expand of the PRK), not the
// raw session_key PRK — the server verifies with k_rpc.
// hmac = base64(HMAC-SHA256(k_rpc,
//                           method || "|" || session_token || "|" || timestamp || "|" || params_json))
// params_json may be "" (treated as "{}"). Success body is NOT scrubbed; caller owns it.
//
// params_json MUST be a syntactically well-formed JSON object (e.g. "{}" or
// {"k":"v"}). This function does NOT validate — callers must pre-validate.
// Passing malformed input will produce a malformed envelope and leak the
// session_token on error.
response call(const char* method,
              const char* session_token,
              const uint8_t* session_key,
              const char* params_json);

} // namespace rpc
