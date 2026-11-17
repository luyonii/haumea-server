#pragma once
// HTTPS client via WinHTTP with TLS 1.3 and certificate pinning.
// All WinHTTP APIs resolved dynamically — no IAT entries for winhttp.dll.

#include <string>
#include <cstdint>

namespace net {

struct response {
    int status_code = 0;   // 0 = network / TLS / pin failure
    std::string body;
};

bool init(const char* server_host, uint16_t port = 443);
response post(const char* path, const std::string& json_body);
void shutdown();

} // namespace net
