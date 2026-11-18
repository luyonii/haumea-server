#pragma once
// Minimal JSON parser/builder for flat objects. Header-only.
// Handles the subset needed by auth and heartbeat: string, int, bool values.

#include <string>
#include <cstdint>
#include <initializer_list>
#include <utility>

namespace json {

// Returns index of the value for `key` at object depth 1 (root object), or npos.
// Skips string contents (honouring \" and \\) and nested {} / [].
inline size_t find_value(const std::string& j, const char* key) {
    const std::string k = key;
    auto ws = [&](size_t p) {
        while (p < j.size() && (j[p] == ' ' || j[p] == '\t' || j[p] == '\n' || j[p] == '\r')) ++p;
        return p;
    };
    int depth = 0;
    for (size_t i = 0; i < j.size(); ++i) {
        char c = j[i];
        if (c == '{' || c == '[') ++depth;
        else if (c == '}' || c == ']') --depth;
        else if (c == '"') {
            size_t s = ++i;
            while (i < j.size() && j[i] != '"') { if (j[i] == '\\') ++i; ++i; }
            if (depth == 1 && i - s == k.size() && j.compare(s, k.size(), k) == 0) {
                size_t p = ws(i + 1);
                if (p < j.size() && j[p] == ':') return ws(p + 1);
            }
        }
    }
    return std::string::npos;
}

inline std::string get_string(const std::string& j, const char* key) {
    auto pos = find_value(j, key);
    if (pos == std::string::npos) return {};
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
    auto pos = find_value(j, key);
    if (pos == std::string::npos) return def;
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
    auto pos = find_value(j, key);
    if (pos == std::string::npos) return def;
    auto term = [&](size_t p) {
        if (p >= j.size()) return true;
        char c = j[p];
        return c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\n' || c == '\r';
    };
    if (pos + 3 < j.size() && j[pos] == 't' && j[pos+1] == 'r' && j[pos+2] == 'u' && j[pos+3] == 'e' && term(pos+4))
        return true;
    if (pos + 4 < j.size() && j[pos] == 'f' && j[pos+1] == 'a' && j[pos+2] == 'l' && j[pos+3] == 's' && j[pos+4] == 'e' && term(pos+5))
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
