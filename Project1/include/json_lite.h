#pragma once
// Minimal JSON parser/builder for flat objects. Header-only.
// Handles the subset needed by auth and heartbeat: string, int, bool values.

#include <string>
#include <cstdint>
#include <initializer_list>
#include <utility>

namespace json {

inline std::string get_string(const std::string& j, const char* key) {
    std::string needle = "\"";
    needle += key;
    needle += "\"";
    auto pos = j.find(needle);
    if (pos == std::string::npos) return {};
    pos = j.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    ++pos;
    while (pos < j.size() && (j[pos] == ' ' || j[pos] == '\t' || j[pos] == '\n' || j[pos] == '\r'))
        ++pos;
    if (pos >= j.size() || j[pos] != '"') return {};
    ++pos;
    std::string r;
    while (pos < j.size() && j[pos] != '"') {
        if (j[pos] == '\\' && pos + 1 < j.size()) {
            ++pos;
            switch (j[pos]) {
            case '"':  r += '"'; break;
            case '\\': r += '\\'; break;
            case '/':  r += '/'; break;
            case 'n':  r += '\n'; break;
            case 'r':  r += '\r'; break;
            case 't':  r += '\t'; break;
            default:   r += j[pos]; break;
            }
        } else {
            r += j[pos];
        }
        ++pos;
    }
    return r;
}

inline int64_t get_int(const std::string& j, const char* key, int64_t def = 0) {
    std::string needle = "\"";
    needle += key;
    needle += "\"";
    auto pos = j.find(needle);
    if (pos == std::string::npos) return def;
    pos = j.find(':', pos + needle.size());
    if (pos == std::string::npos) return def;
    ++pos;
    while (pos < j.size() && (j[pos] == ' ' || j[pos] == '\t')) ++pos;
    bool neg = false;
    if (pos < j.size() && j[pos] == '-') { neg = true; ++pos; }
    if (pos >= j.size() || j[pos] < '0' || j[pos] > '9') return def;
    int64_t v = 0;
    while (pos < j.size() && j[pos] >= '0' && j[pos] <= '9') {
        v = v * 10 + (j[pos] - '0');
        ++pos;
    }
    return neg ? -v : v;
}

inline bool get_bool(const std::string& j, const char* key, bool def = false) {
    std::string needle = "\"";
    needle += key;
    needle += "\"";
    auto pos = j.find(needle);
    if (pos == std::string::npos) return def;
    pos = j.find(':', pos + needle.size());
    if (pos == std::string::npos) return def;
    ++pos;
    while (pos < j.size() && (j[pos] == ' ' || j[pos] == '\t')) ++pos;
    if (pos + 3 < j.size() && j[pos] == 't' && j[pos+1] == 'r' && j[pos+2] == 'u' && j[pos+3] == 'e')
        return true;
    if (pos + 4 < j.size() && j[pos] == 'f' && j[pos+1] == 'a' && j[pos+2] == 'l' && j[pos+3] == 's' && j[pos+4] == 'e')
        return false;
    return def;
}

// Build a flat JSON object. All values are emitted as JSON strings.
inline std::string object(std::initializer_list<std::pair<const char*, std::string>> fields) {
    std::string r = "{";
    bool first = true;
    for (auto& [k, v] : fields) {
        if (!first) r += ',';
        r += '"';
        r += k;
        r += "\":\"";
        for (char c : v) {
            if (c == '"')       r += "\\\"";
            else if (c == '\\') r += "\\\\";
            else                r += c;
        }
        r += '"';
        first = false;
    }
    r += '}';
    return r;
}

} // namespace json
