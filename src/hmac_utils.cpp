#include "hmac_cpp/hmac_utils.hpp"
#include "hmac_cpp/secure_buffer.hpp"
#include <ctime>
#include <cerrno>
#include <stdexcept>
#include <limits>
#include <algorithm>
#include <cstring>

namespace hmac_cpp {
 
    bool constant_time_equals(const uint8_t* a, size_t a_len,
                              const uint8_t* b, size_t b_len) {
        size_t max_len = a_len > b_len ? a_len : b_len;
        unsigned int diff = (a_len != b_len);
        for (size_t i = 0; i < max_len; ++i) {
            unsigned char ac = i < a_len ? a[i] : 0;
            unsigned char bc = i < b_len ? b[i] : 0;
            diff |= ac ^ bc;
        }
        return diff == 0;
    }

    static TypeHash to_type_hash(Pbkdf2Hash prf) {
        switch (prf) {
            case Pbkdf2Hash::Sha1: return TypeHash::SHA1;
            case Pbkdf2Hash::Sha256: return TypeHash::SHA256;
            case Pbkdf2Hash::Sha512: return TypeHash::SHA512;
        }
        throw std::invalid_argument("Unsupported hash type");
    }

    std::vector<uint8_t> pbkdf2(
            const void* password_ptr, size_t password_len,
            const void* salt_ptr, size_t salt_len,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf) {
        if ((password_len > 0 && password_ptr == nullptr) ||
            (salt_len > 0 && salt_ptr == nullptr))
            throw std::invalid_argument("Null pointer with non-zero length");
        if (iterations < 1)
            throw std::invalid_argument("PBKDF2: iterations must be >= 1");
        if (iterations > MAX_PBKDF2_ITERATIONS)
            throw std::invalid_argument("PBKDF2: iterations too large");
        if (dk_len == 0)
            throw std::invalid_argument("PBKDF2: dk_len must be positive");
        if (salt_len < 16)
            throw std::invalid_argument("PBKDF2: salt must be at least 16 bytes");

        size_t hlen = 0;
        TypeHash hash_type = to_type_hash(prf);
        switch (hash_type) {
            case TypeHash::SHA1:
                hlen = hmac_hash::SHA1::DIGEST_SIZE;
                break;
            case TypeHash::SHA256:
                hlen = hmac_hash::SHA256::DIGEST_SIZE;
                break;
            case TypeHash::SHA512:
                hlen = hmac_hash::SHA512::DIGEST_SIZE;
                break;
            default:
                throw std::invalid_argument("Unsupported hash type");
        }

        uint64_t max_dk = (static_cast<uint64_t>(1) << 32) - 1;
        max_dk *= hlen;
        if (dk_len > max_dk)
            throw std::invalid_argument("PBKDF2: dk_len too large");

        size_t l = (dk_len + hlen - 1) / hlen;
        size_t r = dk_len - (l - 1) * hlen;

        std::vector<uint8_t> derived;
        derived.reserve(dk_len);

        std::vector<uint8_t> salt_block;
        salt_block.reserve(salt_len + 4);
        salt_block.insert(salt_block.end(),
                          reinterpret_cast<const uint8_t*>(salt_ptr),
                          reinterpret_cast<const uint8_t*>(salt_ptr) + salt_len);
        salt_block.resize(salt_len + 4);

        for (size_t i = 1; i <= l; ++i) {
            salt_block[salt_len    ] = static_cast<uint8_t>((i >> 24) & 0xFF);
            salt_block[salt_len + 1] = static_cast<uint8_t>((i >> 16) & 0xFF);
            salt_block[salt_len + 2] = static_cast<uint8_t>((i >> 8) & 0xFF);
            salt_block[salt_len + 3] = static_cast<uint8_t>(i & 0xFF);

            secure_buffer<uint8_t> u(std::move(get_hmac(password_ptr, password_len,
                                                         salt_block.data(), salt_block.size(),
                                                         hash_type)));
            secure_buffer<uint8_t> t = u;
            for (uint32_t j = 1; j < iterations; ++j) {
                u = secure_buffer<uint8_t>(get_hmac(password_ptr, password_len,
                                                    u.data(), u.size(), hash_type));
                for (size_t k = 0; k < t.size(); ++k) {
                    t[k] ^= u[k];
                }
            }
            if (i == l) {
                derived.insert(derived.end(), t.begin(), t.begin() + r);
            } else {
                derived.insert(derived.end(), t.begin(), t.end());
            }
            secure_zero(u.data(), u.size());
            secure_zero(t.data(), t.size());
        }
        secure_zero(salt_block.data(), salt_block.size());
        return derived;
    }

    bool pbkdf2_hmac_sha256(const void* password_ptr, size_t password_len,
                            const void* salt_ptr, size_t salt_len,
                            uint32_t iterations, uint8_t* out_ptr, size_t dk_len) noexcept {
        if ((password_len > 0 && password_ptr == nullptr) ||
            (salt_len > 0 && salt_ptr == nullptr) ||
            out_ptr == nullptr)
            return false;
        if (iterations < 1 || dk_len == 0 || salt_len < 16 ||
            iterations > MAX_PBKDF2_ITERATIONS)
            return false;

        const size_t hlen = hmac_hash::SHA256::DIGEST_SIZE;
        uint64_t max_dk = (static_cast<uint64_t>(1) << 32) - 1;
        max_dk *= hlen;
        if (dk_len > max_dk)
            return false;

        size_t l = (dk_len + hlen - 1) / hlen;
        size_t r = dk_len - (l - 1) * hlen;

        std::vector<uint8_t> salt_block;
        salt_block.reserve(salt_len + 4);
        salt_block.insert(salt_block.end(),
                          reinterpret_cast<const uint8_t*>(salt_ptr),
                          reinterpret_cast<const uint8_t*>(salt_ptr) + salt_len);
        salt_block.resize(salt_len + 4);

        size_t pos = 0;
        for (size_t i = 1; i <= l; ++i) {
            salt_block[salt_len    ] = static_cast<uint8_t>((i >> 24) & 0xFF);
            salt_block[salt_len + 1] = static_cast<uint8_t>((i >> 16) & 0xFF);
            salt_block[salt_len + 2] = static_cast<uint8_t>((i >> 8) & 0xFF);
            salt_block[salt_len + 3] = static_cast<uint8_t>(i & 0xFF);

            secure_buffer<uint8_t> u(std::move(get_hmac(password_ptr, password_len,
                                                         salt_block.data(), salt_block.size(),
                                                         TypeHash::SHA256)));
            secure_buffer<uint8_t> t = u;
            for (uint32_t j = 1; j < iterations; ++j) {
                u = secure_buffer<uint8_t>(get_hmac(password_ptr, password_len,
                                                    u.data(), u.size(), TypeHash::SHA256));
                for (size_t k = 0; k < t.size(); ++k) {
                    t[k] ^= u[k];
                }
            }
            size_t take = (i == l) ? r : hlen;
            std::memcpy(out_ptr + pos, t.data(), take);
            pos += take;
            secure_zero(u.data(), u.size());
            secure_zero(t.data(), t.size());
        }
        secure_zero(salt_block.data(), salt_block.size());
        return true;
    }

    std::vector<uint8_t> pbkdf2_with_pepper(
            const void* password_ptr, size_t password_len,
            const void* salt_ptr, size_t salt_len,
            const void* pepper_ptr, size_t pepper_len,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf) {
        TypeHash hash_type = to_type_hash(prf);
        auto pwd_prime = get_hmac(pepper_ptr, pepper_len, password_ptr, password_len, hash_type);
        secure_buffer<uint8_t> tmp(std::move(pwd_prime));
        auto dk = pbkdf2(tmp.data(), tmp.size(), salt_ptr, salt_len, iterations, dk_len, prf);
        secure_zero(tmp.data(), tmp.size());
        return dk;
    }

    std::vector<uint8_t> hkdf_extract_sha256(
            const void* ikm_ptr, size_t ikm_len,
            const void* salt_ptr, size_t salt_len) {
        std::vector<uint8_t> salt_buf;
        if (salt_ptr == nullptr || salt_len == 0) {
            salt_buf.assign(hmac_hash::SHA256::DIGEST_SIZE, 0);
            salt_ptr = salt_buf.data();
            salt_len = salt_buf.size();
        }
        auto prk = get_hmac(salt_ptr, salt_len, ikm_ptr, ikm_len, TypeHash::SHA256);
        return prk;
    }

    std::vector<uint8_t> hkdf_expand_sha256(
            const void* prk_ptr, size_t prk_len,
            const void* info_ptr, size_t info_len,
            size_t L) {
        const size_t HashLen = hmac_hash::SHA256::DIGEST_SIZE;
        if (prk_ptr == nullptr || prk_len != HashLen)
            throw std::invalid_argument("HKDF: prk must be HashLen bytes");
        if (L > 255 * HashLen)
            throw std::invalid_argument("HKDF: L too large");

        std::vector<uint8_t> okm;
        okm.reserve(L);
        std::vector<uint8_t> previous;
        size_t n = (L + HashLen - 1) / HashLen;
        for (size_t i = 1; i <= n; ++i) {
            std::vector<uint8_t> input(previous.begin(), previous.end());
            if (info_ptr && info_len)
                input.insert(input.end(),
                             reinterpret_cast<const uint8_t*>(info_ptr),
                             reinterpret_cast<const uint8_t*>(info_ptr) + info_len);
            input.push_back(static_cast<uint8_t>(i));
            auto t = get_hmac(prk_ptr, prk_len, input.data(), input.size(), TypeHash::SHA256);
            size_t take = (i == n) ? (L - okm.size()) : t.size();
            okm.insert(okm.end(), t.begin(), t.begin() + take);
            previous.assign(t.begin(), t.end());
            secure_zero(t.data(), t.size());
            secure_zero(input.data(), input.size());
        }
        secure_zero(previous.data(), previous.size());
        return okm;
    }

    KeyIv hkdf_key_iv_256(const void* ikm_ptr, size_t ikm_len,
                          const void* salt_ptr, size_t salt_len,
                          const std::string& context) {
        auto prk = hkdf_extract_sha256(ikm_ptr, ikm_len, salt_ptr, salt_len);
        auto okm = hkdf_expand_sha256(prk.data(), prk.size(),
                                      context.data(), context.size(), 44);
        KeyIv out{};
        std::copy(okm.begin(), okm.begin() + 32, out.key.begin());
        std::copy(okm.begin() + 32, okm.begin() + 44, out.iv.begin());
        secure_zero(prk.data(), prk.size());
        secure_zero(okm.data(), okm.size());
        return out;
    }

    std::string generate_time_token(const std::vector<uint8_t> &key, int interval_sec, TypeHash hash_type) {
        if (interval_sec <= 0) {
            throw std::invalid_argument("interval_sec must be positive");
        }
        errno = 0;
        std::time_t now = std::time(nullptr);
        if (now == static_cast<std::time_t>(-1) && errno != 0) {
            throw std::runtime_error("std::time failed");
        }
        std::time_t rounded = now - (now % interval_sec);
        return get_hmac(key, std::to_string(rounded), hash_type);
    }

    bool is_token_valid(const std::string &token, const std::vector<uint8_t> &key, int interval_sec, TypeHash hash_type) {
        if (interval_sec <= 0) {
            throw std::invalid_argument("interval_sec must be positive");
        }
        errno = 0;
        std::time_t now = std::time(nullptr);
        if (now == static_cast<std::time_t>(-1) && errno != 0) {
            throw std::runtime_error("std::time failed");
        }
        std::time_t rounded = now - (now % interval_sec);
        if (constant_time_equals(token, get_hmac(key, std::to_string(rounded), hash_type))) return true;
        if (rounded >= std::numeric_limits<std::time_t>::min() + interval_sec) {
            if (constant_time_equals(token, get_hmac(key, std::to_string(rounded - interval_sec), hash_type))) return true;
        }
        if (rounded <= std::numeric_limits<std::time_t>::max() - interval_sec) {
            if (constant_time_equals(token, get_hmac(key, std::to_string(rounded + interval_sec), hash_type))) return true;
        }
        return false;
    }

    std::string generate_time_token(const std::vector<uint8_t> &key, const std::string &fingerprint, int interval_sec, TypeHash hash_type) {
        if (interval_sec <= 0) {
            throw std::invalid_argument("interval_sec must be positive");
        }
        errno = 0;
        std::time_t now = std::time(nullptr);
        if (now == static_cast<std::time_t>(-1) && errno != 0) {
            throw std::runtime_error("std::time failed");
        }
        std::time_t rounded = now - (now % interval_sec);
        std::string payload = std::to_string(rounded) + "|" + fingerprint;
        return get_hmac(key, payload, hash_type);
    }

    bool is_token_valid(const std::string &token, const std::vector<uint8_t> &key, const std::string &fingerprint, int interval_sec, TypeHash hash_type) {
        if (interval_sec <= 0) {
            throw std::invalid_argument("interval_sec must be positive");
        }
        errno = 0;
        std::time_t now = std::time(nullptr);
        if (now == static_cast<std::time_t>(-1) && errno != 0) {
            throw std::runtime_error("std::time failed");
        }
        std::time_t rounded = now - (now % interval_sec);
        std::string prefix = "|" + fingerprint;
        std::string payload = std::to_string(rounded) + prefix;
        if (constant_time_equals(token, get_hmac(key, payload, hash_type))) return true;
        if (rounded >= std::numeric_limits<std::time_t>::min() + interval_sec) {
            payload = std::to_string(rounded - interval_sec) + prefix;
            if (constant_time_equals(token, get_hmac(key, payload, hash_type))) return true;
        }
        if (rounded <= std::numeric_limits<std::time_t>::max() - interval_sec) {
            payload = std::to_string(rounded + interval_sec) + prefix;
            if (constant_time_equals(token, get_hmac(key, payload, hash_type))) return true;
        }
        return false;
    }

    namespace detail {
        int hotp_from_digest(const std::vector<uint8_t>& hmac_result, int digits) {
            if (hmac_result.empty()) {
                throw std::runtime_error("HOTP: HMAC result too short");
            }
            int offset = hmac_result.back() & 0x0F;
            if (hmac_result.size() < static_cast<size_t>(offset) + 4) {
                throw std::runtime_error("HOTP: HMAC result too short");
            }
            uint32_t bin_code =
                ((hmac_result[offset]     & 0x7F) << 24) |
                ((hmac_result[offset + 1] & 0xFF) << 16) |
                ((hmac_result[offset + 2] & 0xFF) << 8)  |
                ((hmac_result[offset + 3] & 0xFF));
            static const uint64_t divisor[] = {
                10UL, 100UL, 1000UL, 10000UL,
                100000UL, 1000000UL, 10000000UL,
                100000000UL, 1000000000UL
            };
            return bin_code % divisor[digits - 1];
        }
    }

    int get_hotp_code(const void* key_ptr, size_t key_len, uint64_t counter, int digits, TypeHash hash_type) {
        if (digits < 1 || digits > 9) throw std::invalid_argument("HOTP: digits must be in range [1, 9]");

        // Step 1: Pack counter as 8-byte big-endian
        uint8_t counter_bytes[8];
        for (int i = 7; i >= 0; --i) {
            counter_bytes[i] = static_cast<uint8_t>(counter & 0xFF);
            counter >>= 8;
        }

        // Step 2: Compute HMAC
        std::vector<uint8_t> hmac_result = hmac_cpp::get_hmac(key_ptr, key_len, counter_bytes, 8, hash_type);

        // Step 3: Dynamic truncation and modulo
        return detail::hotp_from_digest(hmac_result, digits);
    }

    int get_totp_code_at(
            const void* key_ptr, 
            size_t key_len, 
            uint64_t timestamp,
            int period,
            int digits,
            TypeHash hash_type) {
        // Validate period and digit parameters
        if (period <= 0) {
            throw std::invalid_argument("TOTP: period must be positive");
        }
        if (digits < 1 || digits > 9) {
            throw std::invalid_argument("TOTP: digits must be in range [1, 9]");
        }
        uint64_t counter = timestamp / period;
        return get_hotp_code(key_ptr, key_len, counter, digits, hash_type);
    }
    
    int get_totp_code(
            const void* key_ptr,
            size_t key_len,
            int period,
            int digits,
            TypeHash hash_type) {
        // Validate period and digit parameters
        if (period <= 0) {
            throw std::invalid_argument("TOTP: period must be positive");
        }
        if (digits < 1 || digits > 9) {
            throw std::invalid_argument("TOTP: digits must be in range [1, 9]");
        }
        errno = 0;
        std::time_t now = std::time(nullptr);
        if (now == static_cast<std::time_t>(-1) && errno != 0) {
            throw std::runtime_error("std::time failed");
        }
        if (now < 0) {
            throw std::runtime_error("std::time returned negative value");
        }
        uint64_t timestamp = static_cast<uint64_t>(now);
        return get_totp_code_at(key_ptr, key_len, timestamp, period, digits, hash_type);
    }

    bool is_totp_token_valid(
            int token,
            const void* key_ptr,
            size_t key_len,
            uint64_t timestamp,
            int period,
            int digits,
            TypeHash hash_type) {
        // Validate period and digit parameters
        if (period <= 0) {
            throw std::invalid_argument("TOTP: period must be positive");
        }
        if (digits < 1 || digits > 9) {
            throw std::invalid_argument("TOTP: digits must be in range [1, 9]");
        }
        uint64_t counter = timestamp / period;
        if (token == get_hotp_code(key_ptr, key_len, counter, digits, hash_type)) return true;
        if (counter != std::numeric_limits<uint64_t>::max() &&
            token == get_hotp_code(key_ptr, key_len, counter + 1, digits, hash_type))
            return true;
        if (counter > 0 &&
            token == get_hotp_code(key_ptr, key_len, counter - 1, digits, hash_type))
            return true;
        return false;
    }

    bool is_totp_token_valid(
            int token,
            const void* key_ptr,
            size_t key_len,
            int period,
            int digits,
            TypeHash hash_type) {
        // Validate period and digit parameters
        if (period <= 0) {
            throw std::invalid_argument("TOTP: period must be positive");
        }
        if (digits < 1 || digits > 9) {
            throw std::invalid_argument("TOTP: digits must be in range [1, 9]");
        }
        errno = 0;
        std::time_t now = std::time(nullptr);
        if (now == static_cast<std::time_t>(-1) && errno != 0) {
            throw std::runtime_error("std::time failed");
        }
        if (now < 0) {
            throw std::runtime_error("std::time returned negative value");
        }
        uint64_t timestamp = static_cast<uint64_t>(now);
        uint64_t counter = timestamp / period;
        if (token == get_hotp_code(key_ptr, key_len, counter, digits, hash_type)) return true;
        if (counter != std::numeric_limits<uint64_t>::max() &&
            token == get_hotp_code(key_ptr, key_len, counter + 1, digits, hash_type))
            return true;
        if (counter > 0 &&
            token == get_hotp_code(key_ptr, key_len, counter - 1, digits, hash_type))
            return true;
        return false;
    }

} // namespace hmac_cpp
