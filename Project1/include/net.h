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
// Closes the request handle currently in flight (if any), unblocking a thread
// stuck in WinHttpSendRequest/WinHttpReceiveResponse. Safe to call from any
// thread; safe if nothing is in flight.
void cancel_in_flight();
void shutdown();

} // namespace net
