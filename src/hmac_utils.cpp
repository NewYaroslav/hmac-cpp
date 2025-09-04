#include "hmac_cpp/hmac_utils.hpp"
#include <ctime>
#include <cerrno>
#include <stdexcept>
#include <limits>

namespace hmac_cpp {
 
    bool constant_time_equals(const std::string &a, const std::string &b) {
        size_t max_len = a.size() > b.size() ? a.size() : b.size();
        unsigned int diff = (a.size() != b.size());
        for (size_t i = 0; i < max_len; ++i) {
            unsigned char ac = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
            unsigned char bc = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
            diff |= ac ^ bc;
        }
        return diff == 0;
    }

    std::string generate_time_token(const std::string &key, int interval_sec, TypeHash hash_type) {
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

    bool is_token_valid(const std::string &token, const std::string &key, int interval_sec, TypeHash hash_type) {
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

    std::string generate_time_token(const std::string &key, const std::string &fingerprint, int interval_sec, TypeHash hash_type) {
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

    bool is_token_valid(const std::string &token, const std::string &key, const std::string &fingerprint, int interval_sec, TypeHash hash_type) {
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
