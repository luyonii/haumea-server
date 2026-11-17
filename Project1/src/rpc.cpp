#include "rpc.h"
#include "auth.h"
#include "net.h"
#include "base64.h"
#include "obfstr.h"
#include "dynapi.h"

#include <Windows.h>
#include <cstring>
#include <string>

namespace rpc {

static std::string json_escape(const char* s) {
    std::string r;
    if (!s) return r;
    for (; *s; ++s) {
        char c = *s;
        if (c == '"')       r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else                r += c;
    }
    return r;
}

static std::string now_unix_str() {
    using fn_GSTAFT = void(WINAPI*)(LPFILETIME);
    auto pGS = reinterpret_cast<fn_GSTAFT>(
        dynapi::resolve(dynapi::modules::KERNEL32, API_HASH("GetSystemTimeAsFileTime")));
    if (!pGS) return std::string();
    FILETIME ft{};
    pGS(&ft);
    uint64_t ft100 = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    if (ft100 < 116444736000000000ULL) return std::string();
    uint64_t secs = (ft100 - 116444736000000000ULL) / 10000000ULL;
    if (secs == 0) return std::string();
    char tmp[32]{};
    int n = 0;
    while (secs > 0) { tmp[n++] = static_cast<char>('0' + (secs % 10)); secs /= 10; }
    char buf[32]{};
    int i = 0;
    for (int k = n - 1; k >= 0; --k) buf[i++] = tmp[k];
    return std::string(buf, i);
}

static void scrub_str(std::string& s) {
    if (s.empty()) return;
    volatile char* p = &s[0];
    for (size_t i = 0; i < s.size(); ++i) p[i] = 0;
    s.clear();
}

response call(const char* method,
              const char* session_token,
              const uint8_t* session_key,
              const char* params_json)
{
    response r{};
    if (!method || !session_token || !session_key) {
        r.error = "invalid_args";
        return r;
    }

    const char* params = (params_json && *params_json) ? params_json : "{}";
    std::string ts = now_unix_str();
    if (ts.empty()) {
        r.error = std::string(OBF("time_failed").c_str());
        return r;
    }

    // Canonical message = method || "|" || token || "|" || ts || "|" || params
    // '|' is not a base64 char and not valid in an unquoted JSON field name,
    // so none of the four pieces can forge the delimiter.
    std::string canon;
    canon.reserve(strlen(method) + strlen(session_token) + ts.size() + strlen(params) + 3);
    canon.append(method);
    canon.push_back('|');
    canon.append(session_token);
    canon.push_back('|');
    canon.append(ts);
    canon.push_back('|');
    canon.append(params);

    uint8_t mac[32]{};
    bool ok = auth::hmac_sha256(session_key, 32,
                                reinterpret_cast<const uint8_t*>(canon.data()),
                                canon.size(), mac);
    scrub_str(canon);
    if (!ok) { r.error = "hmac_failed"; return r; }

    std::string hmac_b64 = base64::encode(mac, 32);
    volatile uint8_t* mp = mac;
    for (int i = 0; i < 32; ++i) mp[i] = 0;

    // Build envelope manually: payload must be a raw JSON object, not a string.
    std::string body;
    body.reserve(128 + strlen(params));
    body += '{';
    body += "\""; body += OBF("method").c_str();        body += "\":\""; body += json_escape(method);        body += "\",";
    body += "\""; body += OBF("session_token").c_str(); body += "\":\""; body += json_escape(session_token); body += "\",";
    body += "\""; body += OBF("payload").c_str();       body += "\":";   body += params;                     body += ',';
    body += "\""; body += OBF("timestamp").c_str();     body += "\":\""; body += ts;                         body += "\",";
    body += "\""; body += OBF("hmac").c_str();          body += "\":\""; body += hmac_b64;                   body += "\"";
    body += '}';

    auto resp = net::post(OBF("/api/v1/rpc/call"), body);
    scrub_str(body);
    scrub_str(hmac_b64);
    scrub_str(ts);

    r.status_code = resp.status_code;
    if (resp.status_code != 200) {
        r.error = "http_" + std::to_string(resp.status_code);
        scrub_str(resp.body);
        return r;
    }

    r.success = true;
    r.body = std::move(resp.body); // caller owns and scrubs
    return r;
}

} // namespace rpc
