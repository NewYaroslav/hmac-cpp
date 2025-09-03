#include "hmac_utils.hpp"
#include <chrono>
#include <ctime>
#include <stdexcept>

namespace hmac {

    std::string generate_time_token(const std::string &key, int interval_sec, TypeHash hash_type) {
        if (interval_sec <= 0) {
            throw std::invalid_argument("interval_sec must be positive");
        }
        auto now = std::time(nullptr);
        std::time_t rounded = (now / interval_sec) * interval_sec;
        return get_hmac(key, std::to_string(rounded), hash_type);
    }

    bool is_token_valid(const std::string &token, const std::string &key, int interval_sec, TypeHash hash_type) {
        if (interval_sec <= 0) {
            throw std::invalid_argument("interval_sec must be positive");
        }
        auto now = std::time(nullptr);
        std::time_t rounded = (now / interval_sec) * interval_sec;
        if (token == get_hmac(key, std::to_string(rounded), hash_type)) return true;
        if (token == get_hmac(key, std::to_string(rounded - interval_sec), hash_type)) return true;
        if (token == get_hmac(key, std::to_string(rounded + interval_sec), hash_type)) return true;
        return false;
    }

    std::string generate_time_token(const std::string &key, const std::string &fingerprint, int interval_sec, TypeHash hash_type) {
        if (interval_sec <= 0) {
            throw std::invalid_argument("interval_sec must be positive");
        }
        auto now = std::time(nullptr);
        std::time_t rounded = (now / interval_sec) * interval_sec;
        std::string payload = std::to_string(rounded) + "|" + fingerprint;
        return get_hmac(key, payload, hash_type);
    }

    bool is_token_valid(const std::string &token, const std::string &key, const std::string &fingerprint, int interval_sec, TypeHash hash_type) {
        if (interval_sec <= 0) {
            throw std::invalid_argument("interval_sec must be positive");
        }
        auto now = std::time(nullptr);
        std::time_t rounded = (now / interval_sec) * interval_sec;
        std::string prefix = "|" + fingerprint;
        std::string payload = std::to_string(rounded) + prefix;
        if (token == get_hmac(key, payload, hash_type)) return true;
        payload = std::to_string(rounded - interval_sec) + prefix;
        if (token == get_hmac(key, payload, hash_type)) return true;
        payload = std::to_string(rounded + interval_sec) + prefix;
        if (token == get_hmac(key, payload, hash_type)) return true;
        return false;
    }

    int get_hotp_code(const void* key_ptr, size_t key_len, uint64_t counter, int digits, TypeHash hash_type) {
        if (digits < 1 || digits > 10) throw std::invalid_argument("HOTP: digits must be in range [1, 9]");

        // Step 1: Pack counter as 8-byte big-endian
        uint8_t counter_bytes[8];
        for (int i = 7; i >= 0; --i) {
            counter_bytes[i] = static_cast<uint8_t>(counter & 0xFF);
            counter >>= 8;
        }

        // Step 2: Compute HMAC
        std::vector<uint8_t> hmac_result = hmac::get_hmac(key_ptr, key_len, counter_bytes, 8, hash_type);

        // Step 3: Dynamic truncation
        int offset = hmac_result.back() & 0x0F;
        uint32_t bin_code =
            ((hmac_result[offset]     & 0x7F) << 24) |
            ((hmac_result[offset + 1] & 0xFF) << 16) |
            ((hmac_result[offset + 2] & 0xFF) << 8)  |
            ((hmac_result[offset + 3] & 0xFF));

        // Step 4: Modulo to get N-digit code
        static const uint64_t divisor[] = {
            10UL, 100UL, 1000UL, 10000UL, 
            100000UL, 1000000UL, 10000000UL, 
            100000000UL, 1000000000UL
        };
        return bin_code % divisor[digits - 1];
    }

    int get_totp_code_at(
            const void* key_ptr, 
            size_t key_len, 
            uint64_t timestamp,
            int period, 
            int digits, 
            TypeHash hash_type) {
        if (period <= 0 || digits <= 0 || digits > 10) return 0;
        uint64_t counter = timestamp / period;
        return get_hotp_code(key_ptr, key_len, counter, digits, hash_type);
    }
    
    int get_totp_code(
            const void* key_ptr,
            size_t key_len,
            int period, 
            int digits, 
            TypeHash hash_type) {
        uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));
        return get_totp_code_at(key_ptr, key_len, std::time(nullptr), period, digits, hash_type);
    }

    bool is_totp_token_valid(
            int token,
            const void* key_ptr,
            size_t key_len,
            uint64_t timestamp,
            int period,
            int digits,
            TypeHash hash_type) {
        int64_t counter = static_cast<int64_t>(timestamp / period);
        if (token == get_hotp_code(key_ptr, key_len, static_cast<uint64_t>(counter), digits, hash_type)) return true;
        if (token == get_hotp_code(key_ptr, key_len, static_cast<uint64_t>(counter + 1), digits, hash_type)) return true;
        if (counter > 0 &&
            token == get_hotp_code(key_ptr, key_len, static_cast<uint64_t>(counter - 1), digits, hash_type))
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
        uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr));
        int64_t counter = static_cast<int64_t>(timestamp / period);
        if (token == get_hotp_code(key_ptr, key_len, static_cast<uint64_t>(counter), digits, hash_type)) return true;
        if (token == get_hotp_code(key_ptr, key_len, static_cast<uint64_t>(counter + 1), digits, hash_type)) return true;
        if (counter > 0 &&
            token == get_hotp_code(key_ptr, key_len, static_cast<uint64_t>(counter - 1), digits, hash_type))
            return true;
        return false;
    }

} // namespace hmac
