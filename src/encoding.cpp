#include "hmac_cpp/encoding.hpp"
#include <cstddef>
#include <cstring>
#include <algorithm>

namespace hmac_cpp {

struct _wipe_string_guard {
    std::string& s;
    explicit _wipe_string_guard(std::string& ref) : s(ref) {}
    ~_wipe_string_guard() {
        if (!s.empty()) std::fill(s.begin(), s.end(), '\0');
    }
};

// ======================
// Helpers (Base64)
// ======================

static inline const char* b64_alphabet(Base64Alphabet a) {
    return (a == Base64Alphabet::Standard)
        ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
}

static inline void b64_build_reverse(Base64Alphabet a, int8_t rev[256]) {
    for (int i = 0; i < 256; ++i) rev[i] = -1;
    const char* alpha = b64_alphabet(a);
    for (int i = 0; i < 64; ++i) {
        rev[ static_cast<unsigned char>(alpha[i]) ] = static_cast<int8_t>(i);
    }
    rev[ static_cast<unsigned char>('=') ] = -2; // padding marker
}

std::string base64_encode(const uint8_t* data, size_t len,
                          Base64Alphabet alphabet, bool pad) {
    if (len == 0) return std::string();

    const char* alpha = b64_alphabet(alphabet);

    const size_t full = len / 3;
    const size_t rem  = len % 3;
    const size_t out_len = full * 4 + (rem ? (pad ? 4 : (rem == 1 ? 2 : 3)) : 0);

    std::string out;
    out.resize(out_len);

    size_t ip = 0;
    size_t op = 0;

    for (size_t i = 0; i < full; ++i) {
        const uint32_t n = (static_cast<uint32_t>(data[ip]) << 16) |
                           (static_cast<uint32_t>(data[ip + 1]) << 8) |
                           (static_cast<uint32_t>(data[ip + 2]));
        ip += 3;

        out[op++] = alpha[(n >> 18) & 0x3F];
        out[op++] = alpha[(n >> 12) & 0x3F];
        out[op++] = alpha[(n >> 6)  & 0x3F];
        out[op++] = alpha[(n)       & 0x3F];
    }

    if (rem == 1) {
        uint32_t n = static_cast<uint32_t>(data[ip]) << 16;
        out[op++] = alpha[(n >> 18) & 0x3F];
        out[op++] = alpha[(n >> 12) & 0x3F];
        if (pad) {
            out[op++] = '=';
            out[op++] = '=';
        }
    } else if (rem == 2) {
        uint32_t n = (static_cast<uint32_t>(data[ip]) << 16) |
                     (static_cast<uint32_t>(data[ip + 1]) << 8);
        out[op++] = alpha[(n >> 18) & 0x3F];
        out[op++] = alpha[(n >> 12) & 0x3F];
        out[op++] = alpha[(n >> 6)  & 0x3F];
        if (pad) {
            out[op++] = '=';
        }
    }

    return out;
}

static inline bool is_space(unsigned char c) {
    return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

bool base64_decode(const std::string& in, std::vector<uint8_t>& out,
                   Base64Alphabet alphabet, bool require_padding, bool strict) noexcept {
    out.clear();
    if (in.empty()) return true;

    std::string filtered;
    filtered.reserve(in.size());
    if (strict) {
        filtered.assign(in.begin(), in.end());
    } else {
        for (size_t i = 0; i < in.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(in[i]);
            if (!is_space(c)) filtered.push_back(static_cast<char>(c));
        }
    }
    _wipe_string_guard wipe(filtered);

    const size_t L = filtered.size();
    if (require_padding) {
        if ((L % 4) != 0) return false;
    } else {
        if ((L % 4) == 1) return false;
    }

    int8_t rev[256];
    b64_build_reverse(alphabet, rev);

    size_t approx = (L / 4) * 3 + 3;
    out.reserve(approx);

    size_t i = 0;

    while (i + 4 <= L) {
        int8_t v0 = rev[ static_cast<unsigned char>(filtered[i + 0]) ];
        int8_t v1 = rev[ static_cast<unsigned char>(filtered[i + 1]) ];
        int8_t v2 = rev[ static_cast<unsigned char>(filtered[i + 2]) ];
        int8_t v3 = rev[ static_cast<unsigned char>(filtered[i + 3]) ];
        if (v0 < 0 || v1 < 0) return false;

        bool pad2 = (v2 == -2);
        bool pad3 = (v3 == -2);

        if (pad2) {
            if (i + 4 != L) return false;
            if (v3 != -2) return false;
            uint32_t n = (static_cast<uint32_t>(v0) << 18) |
                         (static_cast<uint32_t>(v1) << 12);
            out.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
            return true;
        } else if (pad3) {
            if (i + 4 != L) return false;
            if (v2 < 0 || v2 == -2) return false;
            uint32_t n = (static_cast<uint32_t>(v0) << 18) |
                         (static_cast<uint32_t>(v1) << 12) |
                         (static_cast<uint32_t>(v2) << 6);
            out.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((n >> 8)  & 0xFF));
            return true;
        } else {
            if (v2 < 0 || v3 < 0) return false;
            uint32_t n = (static_cast<uint32_t>(v0) << 18) |
                         (static_cast<uint32_t>(v1) << 12) |
                         (static_cast<uint32_t>(v2) << 6)  |
                         (static_cast<uint32_t>(v3));
            out.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((n >> 8)  & 0xFF));
            out.push_back(static_cast<uint8_t>((n)       & 0xFF));
        }
        i += 4;
    }

    size_t rem = L - i;
    if (rem == 0) {
        return true;
    }
    if (require_padding) {
        return false;
    }
    if (rem == 2) {
        int8_t v0 = rev[ static_cast<unsigned char>(filtered[i + 0]) ];
        int8_t v1 = rev[ static_cast<unsigned char>(filtered[i + 1]) ];
        if (v0 < 0 || v1 < 0) return false;
        uint32_t n = (static_cast<uint32_t>(v0) << 18) |
                     (static_cast<uint32_t>(v1) << 12);
        out.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
        return true;
    } else if (rem == 3) {
        int8_t v0 = rev[ static_cast<unsigned char>(filtered[i + 0]) ];
        int8_t v1 = rev[ static_cast<unsigned char>(filtered[i + 1]) ];
        int8_t v2 = rev[ static_cast<unsigned char>(filtered[i + 2]) ];
        if (v0 < 0 || v1 < 0 || v2 < 0) return false;
        uint32_t n = (static_cast<uint32_t>(v0) << 18) |
                     (static_cast<uint32_t>(v1) << 12) |
                     (static_cast<uint32_t>(v2) << 6);
        out.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((n >> 8)  & 0xFF));
        return true;
    }
    return false;
}

bool base64_decode(const std::string& in, secure_buffer<uint8_t>& out,
                   Base64Alphabet alphabet, bool require_padding, bool strict) noexcept {
    std::vector<uint8_t> tmp;
    bool ok = base64_decode(in, tmp, alphabet, require_padding, strict);
    if (!ok) {
        out = secure_buffer<uint8_t>();
        return false;
    }
    out = secure_buffer<uint8_t>(tmp.size());
    if (out.size() != tmp.size()) {
        if (!tmp.empty()) std::memset(tmp.data(), 0, tmp.size());
        out = secure_buffer<uint8_t>();
        return false;
    }
    std::memcpy(out.data(), tmp.data(), tmp.size());
    if (!tmp.empty()) std::memset(tmp.data(), 0, tmp.size());
    return true;
}

// ======================
// Base32 (RFC 4648)
// ======================

static inline const char* b32_alphabet() {
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
}

std::string base32_encode(const uint8_t* data, size_t len, bool pad) {
    if (len == 0) return std::string();

    const char* A = b32_alphabet();

    size_t full = len / 5;
    size_t rem  = len % 5;

    size_t tail_chars = 0;
    switch (rem) {
        case 0: tail_chars = 0; break;
        case 1: tail_chars = 2; break;
        case 2: tail_chars = 4; break;
        case 3: tail_chars = 5; break;
        case 4: tail_chars = 7; break;
    }

    size_t out_len = full * 8 + tail_chars;
    if (pad && rem) out_len += (8 - tail_chars);

    std::string out;
    out.resize(out_len);

    size_t ip = 0, op = 0;

    for (size_t i = 0; i < full; ++i) {
        uint32_t b0 = data[ip + 0];
        uint32_t b1 = data[ip + 1];
        uint32_t b2 = data[ip + 2];
        uint32_t b3 = data[ip + 3];
        uint32_t b4 = data[ip + 4];
        ip += 5;

        out[op++] = A[( b0 >> 3 ) & 0x1F];
        out[op++] = A[( (b0 & 0x07) << 2 ) | ( (b1 >> 6) & 0x03 )];
        out[op++] = A[( (b1 >> 1) & 0x1F )];
        out[op++] = A[( (b1 & 0x01) << 4 ) | ( (b2 >> 4) & 0x0F )];
        out[op++] = A[( (b2 & 0x0F) << 1 ) | ( (b3 >> 7) & 0x01 )];
        out[op++] = A[( (b3 >> 2) & 0x1F )];
        out[op++] = A[( (b3 & 0x03) << 3 ) | ( (b4 >> 5) & 0x07 )];
        out[op++] = A[( b4 & 0x1F )];
    }

    if (rem) {
        uint32_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;
        switch (rem) {
            case 1: b0 = data[ip + 0]; break;
            case 2: b0 = data[ip + 0]; b1 = data[ip + 1]; break;
            case 3: b0 = data[ip + 0]; b1 = data[ip + 1]; b2 = data[ip + 2]; break;
            case 4: b0 = data[ip + 0]; b1 = data[ip + 1]; b2 = data[ip + 2]; b3 = data[ip + 3]; break;
        }

        if (rem == 1) {
            out[op++] = A[( b0 >> 3 ) & 0x1F];
            out[op++] = A[( (b0 & 0x07) << 2 )];
            if (pad) { out[op++]='='; out[op++]='='; out[op++]='='; out[op++]='='; out[op++]='='; out[op++]='='; }
        } else if (rem == 2) {
            out[op++] = A[( b0 >> 3 ) & 0x1F];
            out[op++] = A[( (b0 & 0x07) << 2 ) | ( (b1 >> 6) & 0x03 )];
            out[op++] = A[( (b1 >> 1) & 0x1F )];
            out[op++] = A[( (b1 & 0x01) << 4 )];
            if (pad) { out[op++]='='; out[op++]='='; out[op++]='='; out[op++]='='; }
        } else if (rem == 3) {
            out[op++] = A[( b0 >> 3 ) & 0x1F];
            out[op++] = A[( (b0 & 0x07) << 2 ) | ( (b1 >> 6) & 0x03 )];
            out[op++] = A[( (b1 >> 1) & 0x1F )];
            out[op++] = A[( (b1 & 0x01) << 4 ) | ( (b2 >> 4) & 0x0F )];
            out[op++] = A[( (b2 & 0x0F) << 1 )];
            if (pad) { out[op++]='='; out[op++]='='; out[op++]='='; }
        } else if (rem == 4) {
            out[op++] = A[( b0 >> 3 ) & 0x1F];
            out[op++] = A[( (b0 & 0x07) << 2 ) | ( (b1 >> 6) & 0x03 )];
            out[op++] = A[( (b1 >> 1) & 0x1F )];
            out[op++] = A[( (b1 & 0x01) << 4 ) | ( (b2 >> 4) & 0x0F )];
            out[op++] = A[( (b2 & 0x0F) << 1 ) | ( (b3 >> 7) & 0x01 )];
            out[op++] = A[( (b3 >> 2) & 0x1F )];
            out[op++] = A[( (b3 & 0x03) << 3 )];
            if (pad) { out[op++]='='; }
        }
    }

    return out;
}

static inline void b32_build_reverse(int8_t rev[256], bool accept_lower) {
    for (int i = 0; i < 256; ++i) rev[i] = -1;
    const char* A = b32_alphabet();
    for (int i = 0; i < 32; ++i) {
        unsigned char uc = static_cast<unsigned char>(A[i]);
        rev[uc] = static_cast<int8_t>(i);
        if (accept_lower) {
            if (uc >= 'A' && uc <= 'Z') {
                unsigned char lc = static_cast<unsigned char>(uc - 'A' + 'a');
                rev[lc] = static_cast<int8_t>(i);
            }
        }
    }
    rev[ static_cast<unsigned char>('=') ] = -2;
}

bool base32_decode(const std::string& in, std::vector<uint8_t>& out,
                   bool require_padding, bool strict) noexcept {
    out.clear();
    if (in.empty()) return true;

    std::string filtered;
    filtered.reserve(in.size());
    if (strict) {
        filtered.assign(in.begin(), in.end());
    } else {
        for (size_t i = 0; i < in.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(in[i]);
            if (!is_space(c)) filtered.push_back(static_cast<char>(c));
        }
    }
    _wipe_string_guard wipe(filtered);

    const size_t L = filtered.size();
    if (require_padding) {
        if ((L % 8) != 0) return false;
    } else {
        size_t rem = L % 8;
        if (rem == 1 || rem == 3 || rem == 6) return false;
    }

    int8_t rev[256];
    b32_build_reverse(rev, !strict);

    out.reserve((L / 8) * 5 + 5);

    size_t i = 0;

    while (i + 8 <= L) {
        bool has_pad = (filtered[i+0] == '=') || (filtered[i+1] == '=') ||
                       (filtered[i+2] == '=') || (filtered[i+3] == '=') ||
                       (filtered[i+4] == '=') || (filtered[i+5] == '=') ||
                       (filtered[i+6] == '=') || (filtered[i+7] == '=');
        if (has_pad && (i + 8 != L)) return false;

        int8_t c0 = rev[ static_cast<unsigned char>(filtered[i+0]) ];
        int8_t c1 = rev[ static_cast<unsigned char>(filtered[i+1]) ];
        int8_t c2 = rev[ static_cast<unsigned char>(filtered[i+2]) ];
        int8_t c3 = rev[ static_cast<unsigned char>(filtered[i+3]) ];
        int8_t c4 = rev[ static_cast<unsigned char>(filtered[i+4]) ];
        int8_t c5 = rev[ static_cast<unsigned char>(filtered[i+5]) ];
        int8_t c6 = rev[ static_cast<unsigned char>(filtered[i+6]) ];
        int8_t c7 = rev[ static_cast<unsigned char>(filtered[i+7]) ];

        if (c2 == -2) {
            if (!(c0 >= 0 && c1 >= 0) || !(filtered[i+2] == '=' && filtered[i+3] == '=' &&
                                           filtered[i+4] == '=' && filtered[i+5] == '=' &&
                                           filtered[i+6] == '=' && filtered[i+7] == '=')) return false;
            uint8_t b0 = static_cast<uint8_t>(( (c0 << 3) & 0xF8 ) | ( (c1 >> 2) & 0x07 ));
            out.push_back(b0);
            return true;
        } else if (c4 == -2) {
            if (!(c0 >= 0 && c1 >= 0 && c2 >= 0 && c3 >= 0) ||
                !(filtered[i+4] == '=' && filtered[i+5] == '=' &&
                  filtered[i+6] == '=' && filtered[i+7] == '=')) return false;
            uint8_t b0 = static_cast<uint8_t>(( (c0 << 3) & 0xF8 ) | ( (c1 >> 2) & 0x07 ));
            uint8_t b1 = static_cast<uint8_t>(( (c1 & 0x03) << 6 ) | ( (c2 << 1) & 0x7E ) | ( (c3 >> 4) & 0x01 ));
            out.push_back(b0); out.push_back(b1);
            return true;
        } else if (c5 == -2) {
            if (!(c0 >= 0 && c1 >= 0 && c2 >= 0 && c3 >= 0 && c4 >= 0) ||
                !(filtered[i+5] == '=' && filtered[i+6] == '=' && filtered[i+7] == '=')) return false;
            uint8_t b0 = static_cast<uint8_t>(( (c0 << 3) & 0xF8 ) | ( (c1 >> 2) & 0x07 ));
            uint8_t b1 = static_cast<uint8_t>(( (c1 & 0x03) << 6 ) | ( (c2 << 1) & 0x7E ) | ( (c3 >> 4) & 0x01 ));
            uint8_t b2 = static_cast<uint8_t>(( (c3 & 0x0F) << 4 ) | ( (c4 >> 1) & 0x0F ));
            out.push_back(b0); out.push_back(b1); out.push_back(b2);
            return true;
        } else if (c7 == -2) {
            if (!(c0 >= 0 && c1 >= 0 && c2 >= 0 && c3 >= 0 && c4 >= 0 && c5 >= 0 && c6 >= 0) ||
                !(filtered[i+7] == '=')) return false;
            uint8_t b0 = static_cast<uint8_t>(( (c0 << 3) & 0xF8 ) | ( (c1 >> 2) & 0x07 ));
            uint8_t b1 = static_cast<uint8_t>(( (c1 & 0x03) << 6 ) | ( (c2 << 1) & 0x7E ) | ( (c3 >> 4) & 0x01 ));
            uint8_t b2 = static_cast<uint8_t>(( (c3 & 0x0F) << 4 ) | ( (c4 >> 1) & 0x0F ));
            uint8_t b3 = static_cast<uint8_t>(( (c4 & 0x01) << 7 ) | ( (c5 << 2) & 0x7C ) | ( (c6 >> 3) & 0x03 ));
            out.push_back(b0); out.push_back(b1); out.push_back(b2); out.push_back(b3);
            return true;
        } else {
            if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0 || c4 < 0 || c5 < 0 || c6 < 0 || c7 < 0) return false;
            uint8_t b0 = static_cast<uint8_t>(( (c0 << 3) & 0xF8 ) | ( (c1 >> 2) & 0x07 ));
            uint8_t b1 = static_cast<uint8_t>(( (c1 & 0x03) << 6 ) | ( (c2 << 1) & 0x7E ) | ( (c3 >> 4) & 0x01 ));
            uint8_t b2 = static_cast<uint8_t>(( (c3 & 0x0F) << 4 ) | ( (c4 >> 1) & 0x0F ));
            uint8_t b3 = static_cast<uint8_t>(( (c4 & 0x01) << 7 ) | ( (c5 << 2) & 0x7C ) | ( (c6 >> 3) & 0x03 ));
            uint8_t b4 = static_cast<uint8_t>(( (c6 & 0x07) << 5 ) | ( (c7) & 0x1F ));
            out.push_back(b0); out.push_back(b1); out.push_back(b2); out.push_back(b3); out.push_back(b4);
        }
        i += 8;
    }

    size_t rem = L - i;
    if (rem == 0) return true;
    if (require_padding) return false;
    if (!(rem == 2 || rem == 4 || rem == 5 || rem == 7)) return false;

    int8_t c0 = rev[ static_cast<unsigned char>(filtered[i + 0]) ];
    int8_t c1 = rev[ static_cast<unsigned char>(filtered[i + 1]) ];
    if (c0 < 0 || c1 < 0) return false;

    if (rem == 2) {
        uint8_t b0 = static_cast<uint8_t>(( (c0 << 3) & 0xF8 ) | ( (c1 >> 2) & 0x07 ));
        out.push_back(b0);
        return true;
    }

    int8_t c2 = rev[ static_cast<unsigned char>(filtered[i + 2]) ];
    int8_t c3 = rev[ static_cast<unsigned char>(filtered[i + 3]) ];
    if (c2 < 0 || c3 < 0) return false;

    if (rem == 4) {
        uint8_t b0 = static_cast<uint8_t>(( (c0 << 3) & 0xF8 ) | ( (c1 >> 2) & 0x07 ));
        uint8_t b1 = static_cast<uint8_t>(( (c1 & 0x03) << 6 ) | ( (c2 << 1) & 0x7E ) | ( (c3 >> 4) & 0x01 ));
        out.push_back(b0); out.push_back(b1);
        return true;
    }

    int8_t c4 = rev[ static_cast<unsigned char>(filtered[i + 4]) ];
    if (c4 < 0) return false;

    if (rem == 5) {
        uint8_t b0 = static_cast<uint8_t>(( (c0 << 3) & 0xF8 ) | ( (c1 >> 2) & 0x07 ));
        uint8_t b1 = static_cast<uint8_t>(( (c1 & 0x03) << 6 ) | ( (c2 << 1) & 0x7E ) | ( (c3 >> 4) & 0x01 ));
        uint8_t b2 = static_cast<uint8_t>(( (c3 & 0x0F) << 4 ) | ( (c4 >> 1) & 0x0F ));
        out.push_back(b0); out.push_back(b1); out.push_back(b2);
        return true;
    }

    int8_t c5 = rev[ static_cast<unsigned char>(filtered[i + 5]) ];
    int8_t c6 = rev[ static_cast<unsigned char>(filtered[i + 6]) ];
    if (c5 < 0 || c6 < 0) return false;

    uint8_t b0 = static_cast<uint8_t>(( (c0 << 3) & 0xF8 ) | ( (c1 >> 2) & 0x07 ));
    uint8_t b1 = static_cast<uint8_t>(( (c1 & 0x03) << 6 ) | ( (c2 << 1) & 0x7E ) | ( (c3 >> 4) & 0x01 ));
    uint8_t b2 = static_cast<uint8_t>(( (c3 & 0x0F) << 4 ) | ( (c4 >> 1) & 0x0F ));
    uint8_t b3 = static_cast<uint8_t>(( (c4 & 0x01) << 7 ) | ( (c5 << 2) & 0x7C ) | ( (c6 >> 3) & 0x03 ));
    out.push_back(b0); out.push_back(b1); out.push_back(b2); out.push_back(b3);
    return true;
}

bool base32_decode(const std::string& in, secure_buffer<uint8_t>& out,
                   bool require_padding, bool strict) noexcept {
    std::vector<uint8_t> tmp;
    bool ok = base32_decode(in, tmp, require_padding, strict);
    if (!ok) {
        out = secure_buffer<uint8_t>();
        return false;
    }
    out = secure_buffer<uint8_t>(tmp.size());
    if (out.size() != tmp.size()) {
        if (!tmp.empty()) std::memset(tmp.data(), 0, tmp.size());
        out = secure_buffer<uint8_t>();
        return false;
    }
    std::memcpy(out.data(), tmp.data(), tmp.size());
    if (!tmp.empty()) std::memset(tmp.data(), 0, tmp.size());
    return true;
}

} // namespace hmac_cpp

