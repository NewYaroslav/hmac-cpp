#ifndef _HMAC_UTILS_HPP_INCLUDED
#define _HMAC_UTILS_HPP_INCLUDED

#include "hmac.hpp"
#include <string>
#include <vector>

namespace hmac_cpp {

    /// \brief Compares two strings in constant time
    /// \param a First string
    /// \param b Second string
    /// \return true if both strings are equal
    bool constant_time_equals(const std::string &a, const std::string &b);

    /// \brief Derives a key from a password using PBKDF2 (RFC 8018)
    /// \param password_ptr Pointer to the password buffer
    /// \param password_len Length of the password in bytes
    /// \param salt_ptr Pointer to the salt buffer
    /// \param salt_len Length of the salt in bytes
    /// \param iterations Number of iterations, must be positive
    /// \param dk_len Desired length of the derived key in bytes, must be positive
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512)
    /// \return Derived key as a vector of bytes
    std::vector<uint8_t> pbkdf2(
            const void* password_ptr, size_t password_len,
            const void* salt_ptr, size_t salt_len,
            int iterations, size_t dk_len,
            TypeHash hash_type);

    /// \brief Derives a key using PBKDF2 from vector-based password and salt
    template<typename T>
    inline std::vector<uint8_t> pbkdf2(
            const std::vector<T>& password,
            const std::vector<T>& salt,
            int iterations, size_t dk_len,
            TypeHash hash_type) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "pbkdf2(vector<T>) supports only char or uint8_t");
        return pbkdf2(password.data(), password.size(),
                      salt.data(), salt.size(),
                      iterations, dk_len, hash_type);
    }

    /// \brief Derives a key using PBKDF2 from string-based password and salt
    inline std::vector<uint8_t> pbkdf2(
            const std::string& password,
            const std::string& salt,
            int iterations, size_t dk_len,
            TypeHash hash_type) {
        return pbkdf2(password.data(), password.size(),
                      salt.data(), salt.size(),
                      iterations, dk_len, hash_type);
    }

    /// \brief Generates a time-based HMAC-SHA256 token
    /// \param key Secret key used for HMAC
    /// \param interval_sec Interval in seconds that defines token rotation. Must be positive. Default is 60 seconds
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA256
    /// \return Hex-encoded HMAC-SHA256 of the rounded time value
    /// \throws std::runtime_error if the system time cannot be retrieved
    std::string generate_time_token(const std::string &key, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256);

    /// \brief Validates a time-based HMAC-SHA256 token with ±1 interval tolerance
    /// \param token Token received from the client
    /// \param key Secret key used for HMAC
    /// \param interval_sec Interval in seconds that defines token rotation. Must be positive. Default is 60 seconds
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA256
    /// \return true if the token is valid within the ±1 interval range; false otherwise
    /// \throws std::runtime_error if the system time cannot be retrieved
    bool is_token_valid(const std::string &token, const std::string &key, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256);

    /// \brief Generates a time-based HMAC-SHA256 token with fingerprint binding
    /// \param key Secret key used for HMAC
    /// \param fingerprint Unique client identifier (e.g., device ID or session hash)
    /// \param interval_sec Interval in seconds that defines token rotation. Must be positive. Default is 60 seconds
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA256
    /// \return Hex-encoded HMAC-SHA256 of the concatenated timestamp and fingerprint
    /// \throws std::runtime_error if the system time cannot be retrieved
    std::string generate_time_token(const std::string &key, const std::string &fingerprint, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256);

    /// \brief Validates a fingerprint-bound HMAC-SHA256 token with ±1 interval tolerance
    /// \param token Token received from the client
    /// \param key Secret key used for HMAC
    /// \param fingerprint Unique client identifier (e.g., device ID or session hash)
    /// \param interval_sec Interval in seconds that defines token rotation. Must be positive. Default is 60 seconds
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA256
    /// \return true if the token is valid within the ±1 interval range; false otherwise
    /// \throws std::runtime_error if the system time cannot be retrieved
    bool is_token_valid(const std::string &token, const std::string &key, const std::string &fingerprint, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256);
    
    /// \brief Computes HOTP code based on HMAC as defined in RFC 4226
    /// \param key_ptr Pointer to the secret key (raw byte buffer)
    /// \param key_len Length of the secret key in bytes
    /// \param counter 64-bit moving counter (monotonically increasing)
    /// \param digits Desired number of digits in the OTP (typically 6–8, max 9)
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA1
    /// \return One-Time Password (OTP) as an integer in the range [0, 10^digits)
    int get_hotp_code(const void* key_ptr, size_t key_len, uint64_t counter, int digits = 6, TypeHash hash_type = TypeHash::SHA1);

    /// \brief Computes HOTP code from a vector of bytes as key (RFC 4226)
    /// \tparam T Must be either `char` or `uint8_t`
    /// \param key Vector containing the secret key bytes
    /// \param counter 64-bit moving counter (monotonically increasing)
    /// \param digits Desired number of digits in the OTP (typically 6–8, max 9)
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA1
    /// \return One-Time Password (OTP) as an integer in the range [0, 10^digits)
    template<typename T>
    inline int get_hotp_code(const std::vector<T>& key, uint64_t counter, int digits = 6, TypeHash hash_type = TypeHash::SHA1) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "get_hotp_code(vector<T>) supports only char or uint8_t");
        return get_hotp_code(key.data(), key.size(), counter, digits, hash_type);
    }

    /// \brief Computes HOTP code from a std::string key interpreted as raw bytes
    /// \param key Secret key as a binary string (each character is a byte)
    /// \param counter 64-bit moving counter (monotonically increasing)
    /// \param digits Desired number of digits in the OTP (typically 6–8, max 9)
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA1
    /// \return One-Time Password (OTP) as an integer in the range [0, 10^digits)
    inline int get_hotp_code(const std::string& key, uint64_t counter, int digits = 6, TypeHash hash_type = TypeHash::SHA1) {
        return get_hotp_code(key.data(), key.size(), counter, digits, hash_type);
    }

    namespace detail {
        /// \brief Computes HOTP code from a precomputed HMAC digest
        /// \param hmac_result HMAC digest bytes
        /// \param digits Desired number of digits in the OTP (1-9)
        /// \return One-Time Password (OTP) as an integer
        /// \throws std::runtime_error if the digest is too short for dynamic truncation
        int hotp_from_digest(const std::vector<uint8_t>& hmac_result, int digits);
    }
    
    /// \brief Computes TOTP (Time-Based One-Time Password) code for a specific timestamp
    ///        Implements RFC 6238
    /// \param key_ptr Pointer to the secret key
    /// \param key_len Length of the key in bytes
    /// \param timestamp UNIX timestamp in seconds (e.g., time since epoch UTC)
    /// \param period Time step in seconds (default: 30)
    /// \param digits Number of digits in the resulting OTP code (1 to 9, default: 6)
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512; default: SHA1)
    /// \return TOTP code as an integer
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    int get_totp_code_at(
            const void* key_ptr,
            size_t key_len,
            uint64_t  timestamp,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1);
        
    /// \brief Computes TOTP code for a specific timestamp from a vector-based key
    /// \tparam T Must be uint8_t or char
    /// \param key Secret key as a vector
    /// \param timestamp UNIX timestamp in seconds
    /// \param period Time step in seconds (default: 30)
    /// \param digits Number of digits in the resulting OTP code (default: 6)
    /// \param hash_type Hash function to use (default: SHA1)
    /// \return TOTP code as an integer
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    template<typename T>
    inline int get_totp_code_at(
            const std::vector<T>& key,
            uint64_t timestamp,
            int period = 30,
            int digits = 6, 
            TypeHash hash_type = TypeHash::SHA1) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
            "get_totp_code_at(vector<T>) supports only char or uint8_t");
        return get_totp_code_at(key.data(), key.size(), timestamp, period, digits, hash_type);
    }
    
    /// \brief Computes TOTP code for a specific timestamp from a string-based key
    /// \param key Secret key as a binary string
    /// \param timestamp UNIX timestamp in seconds
    /// \param period Time step in seconds (default: 30)
    /// \param digits Number of digits in the resulting OTP code (default: 6)
    /// \param hash_type Hash function to use (default: SHA1)
    /// \return TOTP code as an integer
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    inline int get_totp_code_at(
            const std::string& key,
            uint64_t timestamp,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1) {
        return get_totp_code_at(key.data(), key.size(), timestamp, period, digits, hash_type);
    }
    
    /// \brief Computes current TOTP code using system time (UTC).
    /// \param key_ptr Pointer to secret key buffer.
    /// \param key_len Length of the key in bytes.
    /// \param period Time step in seconds (default: 30).
    /// \param digits Number of digits in the resulting OTP code (default: 6).
    /// \param hash_type Hash function to use (default: SHA1).
    /// \return TOTP code as an integer.
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9].
    /// \throws std::runtime_error if the system time cannot be retrieved.
    int get_totp_code(
            const void* key_ptr,
            size_t key_len,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1);

    /// \brief Computes current TOTP code from a vector-based key using system time (UTC)
    /// \tparam T Must be uint8_t or char
    /// \param key Secret key as a vector
    /// \param period Time step in seconds (default: 30)
    /// \param digits Number of digits in the resulting OTP code (default: 6)
    /// \param hash_type Hash function to use (default: SHA1)
    /// \return TOTP code as an integer
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    /// \throws std::runtime_error if the system time cannot be retrieved
    template<typename T>
    inline int get_totp_code(const std::vector<T>& key, int period = 30, int digits = 6, TypeHash hash_type = TypeHash::SHA1) {
        return get_totp_code(key.data(), key.size(), period, digits, hash_type);
    }

    /// \brief Computes current TOTP code from a string-based key using system time (UTC)
    /// \param key Secret key as a binary string
    /// \param period Time step in seconds (default: 30)
    /// \param digits Number of digits in the resulting OTP code (default: 6)
    /// \param hash_type Hash function to use (default: SHA1)
    /// \return TOTP code as an integer
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    /// \throws std::runtime_error if the system time cannot be retrieved
    inline int get_totp_code(const std::string& key, int period = 30, int digits = 6, TypeHash hash_type = TypeHash::SHA1) {
        return get_totp_code(key.data(), key.size(), period, digits, hash_type);
    }
    
    /// \brief Validates a TOTP token with ±1 time step tolerance (RFC 6238)
    /// \param token OTP code to validate
    /// \param key_ptr Pointer to the secret key buffer
    /// \param key_len Length of the secret key in bytes
    /// \param timestamp Unix timestamp in seconds (e.g., from std::time(nullptr))
    /// \param period Time step in seconds (default: 30)
    /// \param digits Expected number of digits in the OTP (default: 6)
    /// \param hash_type Hash algorithm to use (SHA1, SHA256, SHA512). Default is SHA1
    /// \return true if the token is valid within [-1, 0, +1] time step range; false otherwise.
    ///         The +1 step check is skipped when the computed counter equals
    ///         std::numeric_limits<uint64_t>::max().
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    bool is_totp_token_valid(
            int token,
            const void* key_ptr,
            size_t key_len,
            uint64_t timestamp,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1);

    /// \brief Validates a TOTP token with ±1 time step tolerance
    /// \tparam T Byte type: must be char or uint8_t
    /// \param token OTP code to validate
    /// \param key Secret key as a vector of bytes
    /// \param timestamp Unix timestamp in seconds
    /// \param period Time step in seconds (default: 30)
    /// \param digits Number of digits in the OTP (default: 6)
    /// \param hash_type Hash function to use (default: SHA1)
    /// \return true if the token is valid within [-1, 0, +1] time step range; false otherwise.
    ///         The +1 step check is skipped when the computed counter equals
    ///         std::numeric_limits<uint64_t>::max().
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    template<typename T>
    inline bool is_totp_token_valid(
            int token,
            const std::vector<T>& key,
            uint64_t timestamp,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "is_totp_token_valid(vector<T>) only supports vector<char> or vector<uint8_t>");
        return is_totp_token_valid(token, key.data(), key.size(), timestamp, period, digits, hash_type);
    }
    
    /// \brief Validates a TOTP token with ±1 time step tolerance
    /// \param token OTP code to validate
    /// \param key Secret key as a binary string
    /// \param timestamp Unix timestamp in seconds
    /// \param period Time step in seconds (default: 30)
    /// \param digits Number of digits in the OTP (default: 6)
    /// \param hash_type Hash function to use (default: SHA1)
    /// \return true if the token is valid within [-1, 0, +1] time step range; false otherwise.
    ///         The +1 step check is skipped when the computed counter equals
    ///         std::numeric_limits<uint64_t>::max().
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    inline bool is_totp_token_valid(
            int token,
            const std::string& key,
            uint64_t timestamp,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1) {
        return is_totp_token_valid(token, key.data(), key.size(), timestamp, period, digits, hash_type);
    }
    
    /// \brief Validates a TOTP token with ±1 time step tolerance using current system time
    /// \param token OTP code to validate
    /// \param key_ptr Pointer to the secret key buffer
    /// \param key_len Length of the secret key in bytes
    /// \param period Time step in seconds (default: 30)
    /// \param digits Expected number of digits in the OTP (default: 6)
    /// \param hash_type Hash algorithm to use (default: SHA1)
    /// \return true if the token is valid within [-1, 0, +1] time step range; false otherwise.
    ///         The +1 step check is skipped when the computed counter equals
    ///         std::numeric_limits<uint64_t>::max().
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    /// \throws std::runtime_error if the system time cannot be retrieved
    bool is_totp_token_valid(
            int token,
            const void* key_ptr,
            size_t key_len,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1);
    
    /// \brief Validates a TOTP token with ±1 time step tolerance using current system time
    /// \tparam T Byte type: must be char or uint8_t
    /// \param token OTP code to validate
    /// \param key Secret key as a vector of bytes
    /// \param period Time step in seconds (default: 30)
    /// \param digits Number of digits in the OTP (default: 6)
    /// \param hash_type Hash function to use (default: SHA1)
    /// \return true if the token is valid within [-1, 0, +1] time step range; false otherwise.
    ///         The +1 step check is skipped when the computed counter equals
    ///         std::numeric_limits<uint64_t>::max().
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    /// \throws std::runtime_error if the system time cannot be retrieved
    template<typename T>
    inline bool is_totp_token_valid(
            int token,
            const std::vector<T>& key,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "is_totp_token_valid(vector<T>) only supports vector<char> or vector<uint8_t>");
        return is_totp_token_valid(token, key.data(), key.size(), period, digits, hash_type);
    }
    
    /// \brief Validates a TOTP token with ±1 time step tolerance using current system time
    /// \param token OTP code to validate
    /// \param key Secret key as a binary string
    /// \param period Time step in seconds (default: 30)
    /// \param digits Number of digits in the OTP (default: 6)
    /// \param hash_type Hash function to use (default: SHA1)
    /// \return true if the token is valid within [-1, 0, +1] time step range; false otherwise.
    ///         The +1 step check is skipped when the computed counter equals
    ///         std::numeric_limits<uint64_t>::max().
    /// \throws std::invalid_argument if period <= 0 or digits not in [1,9]
    /// \throws std::runtime_error if the system time cannot be retrieved
    inline bool is_totp_token_valid(
            int token,
            const std::string& key,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1) {
        return is_totp_token_valid(token, key.data(), key.size(), period, digits, hash_type);
    }

} // namespace hmac_cpp
namespace hmac = hmac_cpp;

#endif // _HMAC_UTILS_HPP_INCLUDED
