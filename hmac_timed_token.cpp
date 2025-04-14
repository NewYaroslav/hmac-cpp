#include "hmac_timed_token.hpp"
#include "hmac.hpp"
#include <chrono>
#include <ctime>
#include <string>

namespace hmac {

    std::string generate_time_token(const std::string &key, int interval_sec) {
        auto now = std::time(nullptr);
        std::time_t rounded = (now / interval_sec) * interval_sec;
        return get_hmac(key, std::to_string(rounded), TypeHash::SHA256);
    }

    bool is_token_valid(const std::string &token, const std::string &key, int interval_sec) {
        auto now = std::time(nullptr);
		std::time_t rounded = (now / interval_sec) * interval_sec;
        if (token == get_hmac(key, std::to_string(rounded), TypeHash::SHA256)) return true;
        if (token == get_hmac(key, std::to_string(rounded - interval_sec), TypeHash::SHA256)) return true;
        if (token == get_hmac(key, std::to_string(rounded + interval_sec), TypeHash::SHA256)) return true;
        return false;
    }

    std::string generate_time_token(const std::string &key, const std::string &fingerprint, int interval_sec) {
        auto now = std::time(nullptr);
        std::time_t rounded = (now / interval_sec) * interval_sec;
        std::string payload = std::to_string(rounded) + "|" + fingerprint;
        return get_hmac(key, payload, TypeHash::SHA256);
    }

    bool is_token_valid(const std::string &token, const std::string &key, const std::string &fingerprint, int interval_sec) {
        auto now = std::time(nullptr);
		std::time_t rounded = (now / interval_sec) * interval_sec;
		std::string prefix = "|" + fingerprint;
		std::string payload = std::to_string(rounded) + prefix;
        if (token == get_hmac(key, payload, TypeHash::SHA256)) return true;
		payload = std::to_string(rounded - interval_sec) + prefix;
        if (token == get_hmac(key, payload, TypeHash::SHA256)) return true;
        payload = std::to_string(rounded + interval_sec) + prefix;
        if (token == get_hmac(key, payload, TypeHash::SHA256)) return true;
        return false;
    }

} // namespace hmac
