#ifndef _HMAC_TIMED_TOKEN_HPP_INCLUDED
#define _HMAC_TIMED_TOKEN_HPP_INCLUDED

#include <string>

namespace hmac {

    /// \brief Generates a time-based HMAC-SHA256 token.
    /// \param key Secret key used for HMAC.
    /// \param interval_sec Interval in seconds that defines token rotation. Default is 60 seconds.
    /// \return Hex-encoded HMAC-SHA256 of the rounded time value.
    std::string generate_time_token(const std::string &key, int interval_sec = 60);

    /// \brief Validates a time-based HMAC-SHA256 token with ±1 interval tolerance.
    /// \param token Token received from the client.
    /// \param key Secret key used for HMAC.
    /// \param interval_sec Interval in seconds that defines token rotation. Default is 60 seconds.
    /// \return true if the token is valid within the ±1 interval range; false otherwise.
    bool is_token_valid(const std::string &token, const std::string &key, int interval_sec = 60);

    /// \brief Generates a time-based HMAC-SHA256 token with fingerprint binding.
    /// \param key Secret key used for HMAC.
    /// \param fingerprint Unique client identifier (e.g., device ID or session hash).
    /// \param interval_sec Interval in seconds that defines token rotation. Default is 60 seconds.
    /// \return Hex-encoded HMAC-SHA256 of the concatenated timestamp and fingerprint.
    std::string generate_time_token(const std::string &key, const std::string &fingerprint, int interval_sec = 60);

    /// \brief Validates a fingerprint-bound HMAC-SHA256 token with ±1 interval tolerance.
    /// \param token Token received from the client.
    /// \param key Secret key used for HMAC.
    /// \param fingerprint Unique client identifier (e.g., device ID or session hash).
    /// \param interval_sec Interval in seconds that defines token rotation. Default is 60 seconds.
    /// \return true if the token is valid within the ±1 interval range; false otherwise.
    bool is_token_valid(const std::string &token, const std::string &key, const std::string &fingerprint, int interval_sec = 60);

} // namespace hmac

#endif // _HMAC_TIMED_TOKEN_HPP_INCLUDED
