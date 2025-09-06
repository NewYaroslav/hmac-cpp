#ifndef _HMAC_UTILS_HPP_INCLUDED
#define _HMAC_UTILS_HPP_INCLUDED

#include "hmac.hpp"
#include "secure_buffer.hpp"
#include <array>
#include <string>
#include <vector>

#ifndef HMAC_CPP_MAX_PBKDF2_ITERATIONS
#define HMAC_CPP_MAX_PBKDF2_ITERATIONS 1000000u
#endif

namespace hmac_cpp {

    static constexpr uint32_t MAX_PBKDF2_ITERATIONS = HMAC_CPP_MAX_PBKDF2_ITERATIONS;

    /// \brief Compares two byte arrays in constant time
    /// \param a Pointer to first array
    /// \param a_len Length of the first array
    /// \param b Pointer to second array
    /// \param b_len Length of the second array
    /// \return true if both arrays are equal
    HMAC_CPP_API bool constant_time_equals(const uint8_t* a, size_t a_len,
                              const uint8_t* b, size_t b_len);

    /// \brief Alias for \c constant_time_equals.
    /// \param a Pointer to first array.
    /// \param a_len Length of the first array.
    /// \param b Pointer to second array.
    /// \param b_len Length of the second array.
    /// \return true if both arrays are equal.
    /// \note Avoids early length checks; input lengths are treated as public
    ///       and may influence timing.
    HMAC_CPP_API bool constant_time_equal(const uint8_t* a, size_t a_len,
                                          const uint8_t* b, size_t b_len);

    /// \brief Compare vectors in constant time.
    /// \param a First vector.
    /// \param b Second vector.
    /// \return true if both vectors are equal.
    inline bool constant_time_equals(const std::vector<uint8_t>& a,
                                     const std::vector<uint8_t>& b) {
        return constant_time_equals(a.data(), a.size(), b.data(), b.size());
    }

    /// \brief Compare strings in constant time.
    /// \param a First string.
    /// \param b Second string.
    /// \return true if both strings are equal.
    inline bool constant_time_equals(const std::string &a, const std::string &b) {
        return constant_time_equals(reinterpret_cast<const uint8_t*>(a.data()), a.size(),
                                    reinterpret_cast<const uint8_t*>(b.data()), b.size());
    }

    /// \brief Alias for \c constant_time_equal on vectors.
    /// \param a First vector.
    /// \param b Second vector.
    /// \return true if both vectors are equal.
    inline bool constant_time_equal(const std::vector<uint8_t>& a,
                                    const std::vector<uint8_t>& b) {
        return constant_time_equal(a.data(), a.size(), b.data(), b.size());
    }

    /// \brief Alias for \c constant_time_equal on strings.
    /// \param a First string.
    /// \param b Second string.
    /// \return true if both strings are equal.
    inline bool constant_time_equal(const std::string& a, const std::string& b) {
        return constant_time_equal(reinterpret_cast<const uint8_t*>(a.data()), a.size(),
                                   reinterpret_cast<const uint8_t*>(b.data()), b.size());
    }

    /// \brief Hash choices for PBKDF2
    enum class Pbkdf2Hash { Sha1, Sha256, Sha512 };
  
    /// PBKDF2 Security Notes:
    /// - Use a random salt of at least 16 bytes and never reuse it.
    /// - PBKDF2 is CPU-bound; prefer Argon2 or scrypt for user passwords when available.
    /// - Choose iterations so the derivation takes about 200–500 ms on 2025 hardware.
    /// - Store {salt, iterations} with the ciphertext or hash; these values are public.
    /// - Salts and iteration counts must be unique per password.
    /// - Example serialization: {magic|ver|prf|salt|iters|dkLen|…}.

    /// \brief Result of PBKDF2 derivation.
    struct Pbkdf2Result {
        std::vector<uint8_t> salt;
        uint32_t iters;
        std::vector<uint8_t> key;
    };

    /// \brief Derives a key from a password using PBKDF2 (RFC 8018)
    /// \param password_ptr Pointer to the password buffer
    /// \param password_len Length of the password in bytes
    /// \param salt_ptr Pointer to the salt buffer
    /// \param salt_len Length of the salt in bytes
    /// \param iterations Number of iterations, must be positive
    /// \param dk_len Desired length of the derived key in bytes, must be positive
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512)
    /// \return Derived key as a vector of bytes
    HMAC_CPP_API std::vector<uint8_t> pbkdf2(
            const void* password_ptr, size_t password_len,
            const void* salt_ptr, size_t salt_len,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256);

    /// \brief Derive key using PBKDF2 from vector-based password and salt.
    /// \tparam T Byte type; must be char or uint8_t.
    /// \param password Password bytes.
    /// \param salt Salt bytes.
    /// \param iterations Number of iterations.
    /// \param dk_len Desired key length in bytes.
    /// \param prf Hash function to use.
    /// \return Derived key as byte vector.
    template<typename T>
    inline std::vector<uint8_t> pbkdf2(
            const std::vector<T>& password,
            const std::vector<T>& salt,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "pbkdf2(vector<T>) supports only char or uint8_t");
        return pbkdf2(password.data(), password.size(),
                      salt.data(), salt.size(),
                      iterations, dk_len, prf);
    }

    /// \brief Derive key using PBKDF2 from string-based password and salt.
    /// \param password Password bytes as string.
    /// \param salt Salt bytes as string.
    /// \param iterations Number of iterations.
    /// \param dk_len Desired key length in bytes.
    /// \param prf Hash function to use.
    /// \return Derived key as byte vector.
    /// \deprecated Use overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline std::vector<uint8_t> pbkdf2(
            const std::string& password,
            const std::string& salt,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256) {
        return pbkdf2(password.data(), password.size(),
                      salt.data(), salt.size(),
                      iterations, dk_len, prf);
    }

    /// \brief Derive key using PBKDF2 from secure_buffer inputs.
    /// \param password Password bytes.
    /// \param salt Salt bytes.
    /// \param iterations Number of iterations.
    /// \param dk_len Desired key length in bytes.
    /// \param prf Hash function to use.
    /// \return Derived key as byte vector.
    inline std::vector<uint8_t> pbkdf2(
            const secure_buffer<uint8_t>& password,
            const secure_buffer<uint8_t>& salt,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256) {
        return pbkdf2(password.data(), password.size(),
                      salt.data(), salt.size(),
                      iterations, dk_len, prf);
    }

    /// \brief Derive key using stored PBKDF2 parameters and vector password.
    /// \tparam T Byte type; must be char or uint8_t.
    /// \param password Password bytes.
    /// \param params Salt, iteration count and key size.
    /// \param prf Hash function to use.
    /// \return Result structure containing salt, iterations and key.
    template<typename T>
    inline Pbkdf2Result pbkdf2(
            const std::vector<T>& password,
            const Pbkdf2Result& params,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "pbkdf2(vector<T>) supports only char or uint8_t");
        auto key = pbkdf2(password.data(), password.size(),
                          params.salt.data(), params.salt.size(),
                          params.iters, params.key.size(), prf);
        return {params.salt, params.iters, std::move(key)};
    }

    /// \brief Derive key using stored PBKDF2 parameters and string password.
    /// \param password Password bytes as string.
    /// \param params Salt, iteration count and key size.
    /// \param prf Hash function to use.
    /// \return Result structure containing salt, iterations and key.
    inline Pbkdf2Result pbkdf2(
            const std::string& password,
            const Pbkdf2Result& params,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256) {
        auto key = pbkdf2(password.data(), password.size(),
                          params.salt.data(), params.salt.size(),
                          params.iters, params.key.size(), prf);
        return {params.salt, params.iters, std::move(key)};
    }

    /// \brief Derive key using stored PBKDF2 parameters and secure_buffer password.
    /// \param password Password bytes.
    /// \param params Salt, iteration count and key size.
    /// \param prf Hash function to use.
    /// \return Result structure containing salt, iterations and key.
    inline Pbkdf2Result pbkdf2(
            const secure_buffer<uint8_t>& password,
            const Pbkdf2Result& params,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256) {
        auto key = pbkdf2(password.data(), password.size(),
                          params.salt.data(), params.salt.size(),
                          params.iters, params.key.size(), prf);
        return {params.salt, params.iters, std::move(key)};
    }

    /// \brief Derives PBKDF2 into caller-provided buffer using selected hash.
    /// \param prf Hash function to use (SHA1, SHA256, SHA512)
    /// \param password_ptr Pointer to the password buffer
    /// \param password_len Length of the password in bytes
    /// \param salt_ptr Pointer to the salt buffer
    /// \param salt_len Length of the salt in bytes
    /// \param iterations Number of iterations, must be positive
    /// \param out_ptr Output buffer for derived key
    /// \param dk_len Length of output buffer in bytes, must be positive
    /// \return true on success, false on invalid parameters
    HMAC_CPP_API bool pbkdf2(Pbkdf2Hash prf,
                const void* password_ptr, size_t password_len,
                const void* salt_ptr, size_t salt_len,
                uint32_t iterations, uint8_t* out_ptr, size_t dk_len) noexcept;

    /// \brief Derive PBKDF2 into array using string inputs.
    /// \tparam N Output array size.
    /// \param prf Hash function to use.
    /// \param password Password bytes as string.
    /// \param salt Salt bytes as string.
    /// \param iterations Number of iterations.
    /// \param out Output array for derived key.
    /// \return true on success, false on invalid parameters.
    /// \deprecated Use overloads that accept std::vector<uint8_t> or secure_buffer.
    template<size_t N>
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline bool pbkdf2(Pbkdf2Hash prf,
                       const std::string& password,
                       const std::string& salt,
                       uint32_t iterations,
                       std::array<uint8_t, N>& out) noexcept {
        return pbkdf2(prf, password.data(), password.size(),
                      salt.data(), salt.size(),
                      iterations, out.data(), out.size());
    }

    /// \brief Derive PBKDF2 into caller buffer using secure_buffer inputs.
    /// \param prf Hash function to use.
    /// \param password Password bytes.
    /// \param salt Salt bytes.
    /// \param iterations Number of iterations.
    /// \param out_ptr Output buffer for derived key.
    /// \param dk_len Length of output buffer in bytes.
    /// \return true on success, false on invalid parameters.
    inline bool pbkdf2(Pbkdf2Hash prf,
                       const secure_buffer<uint8_t>& password,
                       const secure_buffer<uint8_t>& salt,
                       uint32_t iterations,
                       uint8_t* out_ptr, size_t dk_len) noexcept {
        return pbkdf2(prf, password.data(), password.size(),
                      salt.data(), salt.size(),
                      iterations, out_ptr, dk_len);
    }

    /// \brief Derive PBKDF2 into array using secure_buffer inputs.
    /// \tparam N Output array size.
    /// \param prf Hash function to use.
    /// \param password Password bytes.
    /// \param salt Salt bytes.
    /// \param iterations Number of iterations.
    /// \param out Output array for derived key.
    /// \return true on success, false on invalid parameters.
    template<size_t N>
    inline bool pbkdf2(Pbkdf2Hash prf,
                       const secure_buffer<uint8_t>& password,
                       const secure_buffer<uint8_t>& salt,
                       uint32_t iterations,
                       std::array<uint8_t, N>& out) noexcept {
        return pbkdf2(prf, password.data(), password.size(),
                      salt.data(), salt.size(),
                      iterations, out.data(), out.size());
    }

    /// \brief Derives PBKDF2-HMAC-SHA256 into caller-provided buffer
    /// \param password_ptr Pointer to the password buffer
    /// \param password_len Length of the password in bytes
    /// \param salt_ptr Pointer to the salt buffer
    /// \param salt_len Length of the salt in bytes
    /// \param iterations Number of iterations, must be positive
    /// \param out_ptr Output buffer for derived key
    /// \param dk_len Length of output buffer in bytes, must be positive
    /// \return true on success, false on invalid parameters
    HMAC_CPP_API bool pbkdf2_hmac_sha256(const void* password_ptr, size_t password_len,
                            const void* salt_ptr, size_t salt_len,
                            uint32_t iterations, uint8_t* out_ptr, size_t dk_len) noexcept;

    /// \brief Derive PBKDF2-HMAC-SHA256 into array using string inputs.
    /// \tparam N Output array size.
    /// \param password Password bytes as string.
    /// \param salt Salt bytes as string.
    /// \param iterations Number of iterations.
    /// \param out Output array for derived key.
    /// \return true on success, false on invalid parameters.
    /// \deprecated Use overloads that accept std::vector<uint8_t> or secure_buffer.
    template<size_t N>
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline bool pbkdf2_hmac_sha256(const std::string& password,
                                   const std::string& salt,
                                   uint32_t iterations,
                                   std::array<uint8_t, N>& out) noexcept {
        return pbkdf2_hmac_sha256(password.data(), password.size(),
                                  salt.data(), salt.size(),
                                  iterations, out.data(), out.size());
    }

    /// \brief PBKDF2-HMAC-SHA256 with secure_buffer inputs.
    /// \param password Password bytes.
    /// \param salt Salt bytes.
    /// \param iterations Number of iterations.
    /// \param out_ptr Output buffer for derived key.
    /// \param dk_len Length of output buffer in bytes.
    /// \return true on success, false on invalid parameters.
    inline bool pbkdf2_hmac_sha256(const secure_buffer<uint8_t>& password,
                                   const secure_buffer<uint8_t>& salt,
                                   uint32_t iterations,
                                   uint8_t* out_ptr, size_t dk_len) noexcept {
        return pbkdf2_hmac_sha256(password.data(), password.size(),
                                  salt.data(), salt.size(),
                                  iterations, out_ptr, dk_len);
    }

    /// \brief PBKDF2-HMAC-SHA256 with secure_buffer inputs.
    /// \tparam N Length of the output array.
    /// \param password Password bytes.
    /// \param salt Salt bytes.
    /// \param iterations Number of iterations.
    /// \param out Output array for derived key.
    /// \return true on success, false on invalid parameters.
    template<size_t N>
    inline bool pbkdf2_hmac_sha256(const secure_buffer<uint8_t>& password,
                                   const secure_buffer<uint8_t>& salt,
                                   uint32_t iterations,
                                   std::array<uint8_t, N>& out) noexcept {
        return pbkdf2_hmac_sha256(password.data(), password.size(),
                                  salt.data(), salt.size(),
                                  iterations, out.data(), out.size());
    }

    /// \brief Derives a key using PBKDF2 with an additional pepper value.
    /// \param password_ptr Pointer to the password buffer.
    /// \param password_len Length of the password in bytes.
    /// \param salt_ptr Pointer to the salt buffer.
    /// \param salt_len Length of the salt in bytes.
    /// \param pepper_ptr Pointer to the pepper buffer.
    /// \param pepper_len Length of the pepper in bytes.
    /// \param iterations Number of iterations, must be positive.
    /// \param dk_len Desired length of the derived key in bytes, must be positive.
    /// \param prf Hash function to use (SHA1, SHA256, SHA512).
    /// \return Derived key as a vector of bytes.
    HMAC_CPP_API std::vector<uint8_t> pbkdf2_with_pepper(
            const void* password_ptr, size_t password_len,
            const void* salt_ptr, size_t salt_len,
            const void* pepper_ptr, size_t pepper_len,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256);

    /// \brief PBKDF2 with pepper using vector-based inputs.
    /// \tparam T Byte type; must be char or uint8_t.
    /// \param password Password bytes.
    /// \param salt Salt bytes.
    /// \param pepper Pepper bytes.
    /// \param iterations Number of iterations.
    /// \param dk_len Desired length of the derived key in bytes.
    /// \param prf Hash function to use.
    /// \return Derived key as a vector of bytes.
    template<typename T>
    inline std::vector<uint8_t> pbkdf2_with_pepper(
            const std::vector<T>& password,
            const std::vector<T>& salt,
            const std::vector<T>& pepper,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "pbkdf2_with_pepper(vector<T>) supports only char or uint8_t");
        return pbkdf2_with_pepper(password.data(), password.size(),
                                  salt.data(), salt.size(),
                                  pepper.data(), pepper.size(),
                                  iterations, dk_len, prf);
    }

    /// \brief Derive key using PBKDF2 with pepper from string inputs.
    /// \param password Password bytes as string.
    /// \param salt Salt bytes as string.
    /// \param pepper Pepper bytes as string.
    /// \param iterations Number of iterations.
    /// \param dk_len Desired length of derived key in bytes.
    /// \param prf Hash function to use.
    /// \return Derived key as byte vector.
    /// \deprecated Use overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline std::vector<uint8_t> pbkdf2_with_pepper(
            const std::string& password,
            const std::string& salt,
            const std::string& pepper,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256) {
        return pbkdf2_with_pepper(password.data(), password.size(),
                                  salt.data(), salt.size(),
                                  pepper.data(), pepper.size(),
                                  iterations, dk_len, prf);
    }

    /// \brief Derives a key using PBKDF2 with pepper from secure buffers.
    /// \param password Password bytes.
    /// \param salt Salt bytes.
    /// \param pepper Pepper bytes.
    /// \param iterations Number of iterations.
    /// \param dk_len Desired length of the derived key in bytes.
    /// \param prf Hash function to use.
    /// \return Derived key as a vector of bytes.
    inline std::vector<uint8_t> pbkdf2_with_pepper(
            const secure_buffer<uint8_t>& password,
            const secure_buffer<uint8_t>& salt,
            const secure_buffer<uint8_t>& pepper,
            uint32_t iterations, size_t dk_len,
            Pbkdf2Hash prf = Pbkdf2Hash::Sha256) {
        return pbkdf2_with_pepper(password.data(), password.size(),
                                  salt.data(), salt.size(),
                                  pepper.data(), pepper.size(),
                                  iterations, dk_len, prf);
    }

    /// \brief HKDF extract step using SHA-256.
    /// \param ikm_ptr Pointer to input keying material.
    /// \param ikm_len Length of the input keying material.
    /// \param salt_ptr Pointer to optional salt buffer (may be null when salt_len is 0).
    /// \param salt_len Length of the salt in bytes.
    /// \return Pseudorandom key (PRK) as a byte vector.
    HMAC_CPP_API std::vector<uint8_t> hkdf_extract_sha256(
            const void* ikm_ptr, size_t ikm_len,
            const void* salt_ptr, size_t salt_len);

    /// \brief HKDF extract step using vector inputs.
    /// \param ikm Input keying material.
    /// \param salt Salt bytes.
    /// \return Pseudorandom key.
    inline std::vector<uint8_t> hkdf_extract_sha256(
            const std::vector<uint8_t>& ikm,
            const std::vector<uint8_t>& salt) {
        return hkdf_extract_sha256(ikm.data(), ikm.size(), salt.data(), salt.size());
    }

    /// \brief HKDF expand step using SHA-256.
    /// \param prk_ptr Pointer to the pseudorandom key.
    /// \param prk_len Length of the pseudorandom key.
    /// \param info_ptr Optional context and application specific information (can be null).
    /// \param info_len Length of the info buffer in bytes.
    /// \param L Length of output keying material in bytes.
    /// \return Output keying material as a byte vector.
    HMAC_CPP_API std::vector<uint8_t> hkdf_expand_sha256(
            const void* prk_ptr, size_t prk_len,
            const void* info_ptr, size_t info_len,
            size_t L);

    /// \brief HKDF expand step using vector inputs.
    /// \param prk Pseudorandom key.
    /// \param info Context information.
    /// \param L Output key length in bytes.
    /// \return Output keying material.
    inline std::vector<uint8_t> hkdf_expand_sha256(
            const std::vector<uint8_t>& prk,
            const std::vector<uint8_t>& info,
            size_t L) {
        return hkdf_expand_sha256(prk.data(), prk.size(), info.data(), info.size(), L);
    }

    /// \brief Holds a 32-byte key and 12-byte IV produced by HKDF.
    struct KeyIv {
        std::array<uint8_t,32> key; ///< Derived symmetric key
        std::array<uint8_t,12> iv;  ///< Derived initialization vector
    };

    /// \brief Derives a 32-byte key and 12-byte IV using HKDF-SHA256.
    /// \param ikm_ptr Pointer to input keying material.
    /// \param ikm_len Length of the input keying material.
    /// \param salt_ptr Pointer to the salt buffer.
    /// \param salt_len Length of the salt in bytes.
    /// \param context Application-specific context string.
    /// \return Struct containing the derived key and IV.
    KeyIv hkdf_key_iv_256(const void* ikm_ptr, size_t ikm_len,
                          const void* salt_ptr, size_t salt_len,
                          const std::string& context);

    /// \brief Derive key and IV using vector inputs.
    /// \param ikm Input keying material.
    /// \param salt Salt bytes.
    /// \param context Application-specific context string.
    /// \return Derived key and IV.
    inline KeyIv hkdf_key_iv_256(const std::vector<uint8_t>& ikm,
                                 const std::vector<uint8_t>& salt,
                                 const std::string& context) {
        return hkdf_key_iv_256(ikm.data(), ikm.size(), salt.data(), salt.size(), context);
    }

    /// \brief Generates a time-based HMAC-SHA256 token
    /// \param key Secret key used for HMAC
    /// \param interval_sec Interval in seconds that defines token rotation. Must be positive. Default is 60 seconds
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA256
    /// \return Hex-encoded HMAC-SHA256 of the rounded time value
    /// \throws std::runtime_error if the system time cannot be retrieved
    HMAC_CPP_API std::string generate_time_token(const std::vector<uint8_t>& key, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256);

    inline std::string generate_time_token(const secure_buffer<uint8_t>& key, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256) {
        return generate_time_token(std::vector<uint8_t>(key.begin(), key.end()), interval_sec, hash_type);
    }

    /// \brief Generate time token using string key.
    /// \param key Secret key as string.
    /// \param interval_sec Token rotation interval in seconds.
    /// \param hash_type Hash function to use.
    /// \return Hex-encoded token.
    /// \deprecated Prefer overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline std::string generate_time_token(const std::string &key, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256) {
        return generate_time_token(std::vector<uint8_t>(key.begin(), key.end()), interval_sec, hash_type);
    }

    /// \brief Validates a time-based HMAC-SHA256 token with ±1 interval tolerance
    /// \param token Token received from the client
    /// \param key Secret key used for HMAC
    /// \param interval_sec Interval in seconds that defines token rotation. Must be positive. Default is 60 seconds
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA256
    /// \return true if the token is valid within the ±1 interval range; false otherwise
    /// \throws std::runtime_error if the system time cannot be retrieved
    HMAC_CPP_API bool is_token_valid(const std::string &token, const std::vector<uint8_t>& key, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256);
    inline bool is_token_valid(const std::string &token, const secure_buffer<uint8_t>& key, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256) {
        return is_token_valid(token, std::vector<uint8_t>(key.begin(), key.end()), interval_sec, hash_type);
    }

    /// \brief Validate time token using string key.
    /// \param token Token to validate.
    /// \param key Secret key as string.
    /// \param interval_sec Token rotation interval in seconds.
    /// \param hash_type Hash function to use.
    /// \return true if token is valid.
    /// \deprecated Prefer overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline bool is_token_valid(const std::string &token, const std::string &key, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256) {
        return is_token_valid(token, std::vector<uint8_t>(key.begin(), key.end()), interval_sec, hash_type);
    }

    /// \brief Generates a time-based HMAC-SHA256 token with fingerprint binding
    /// \param key Secret key used for HMAC
    /// \param fingerprint Unique client identifier (e.g., device ID or session hash)
    /// \param interval_sec Interval in seconds that defines token rotation. Must be positive. Default is 60 seconds
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA256
    /// \return Hex-encoded HMAC-SHA256 of the concatenated timestamp and fingerprint
    /// \throws std::runtime_error if the system time cannot be retrieved
    HMAC_CPP_API std::string generate_time_token(const std::vector<uint8_t>& key, const std::string &fingerprint, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256);

    inline std::string generate_time_token(const secure_buffer<uint8_t>& key, const std::string &fingerprint, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256) {
        return generate_time_token(std::vector<uint8_t>(key.begin(), key.end()), fingerprint, interval_sec, hash_type);
    }

    /// \brief Generate fingerprint-bound token using string key.
    /// \param key Secret key as string.
    /// \param fingerprint Client identifier.
    /// \param interval_sec Token rotation interval in seconds.
    /// \param hash_type Hash function to use.
    /// \return Hex-encoded token.
    /// \deprecated Prefer overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline std::string generate_time_token(const std::string &key, const std::string &fingerprint, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256) {
        return generate_time_token(std::vector<uint8_t>(key.begin(), key.end()), fingerprint, interval_sec, hash_type);
    }

    /// \brief Validates a fingerprint-bound HMAC-SHA256 token with ±1 interval tolerance
    /// \param token Token received from the client
    /// \param key Secret key used for HMAC
    /// \param fingerprint Unique client identifier (e.g., device ID or session hash)
    /// \param interval_sec Interval in seconds that defines token rotation. Must be positive. Default is 60 seconds
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA256
    /// \return true if the token is valid within the ±1 interval range; false otherwise
    /// \throws std::runtime_error if the system time cannot be retrieved
    HMAC_CPP_API bool is_token_valid(const std::string &token, const std::vector<uint8_t>& key, const std::string &fingerprint, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256);

    inline bool is_token_valid(const std::string &token, const secure_buffer<uint8_t>& key, const std::string &fingerprint, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256) {
        return is_token_valid(token, std::vector<uint8_t>(key.begin(), key.end()), fingerprint, interval_sec, hash_type);
    }

    /// \brief Validate fingerprint-bound token using string key.
    /// \param token Token to validate.
    /// \param key Secret key as string.
    /// \param fingerprint Client identifier.
    /// \param interval_sec Token rotation interval in seconds.
    /// \param hash_type Hash function to use.
    /// \return true if token is valid.
    /// \deprecated Prefer overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline bool is_token_valid(const std::string &token, const std::string &key, const std::string &fingerprint, int interval_sec = 60, TypeHash hash_type = TypeHash::SHA256) {
        return is_token_valid(token, std::vector<uint8_t>(key.begin(), key.end()), fingerprint, interval_sec, hash_type);
    }
    
    /// \brief Computes HOTP code based on HMAC as defined in RFC 4226
    /// \param key_ptr Pointer to the secret key (raw byte buffer)
    /// \param key_len Length of the secret key in bytes
    /// \param counter 64-bit moving counter (monotonically increasing)
    /// \param digits Desired number of digits in the OTP (typically 6–8, max 9)
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA1
    /// \return One-Time Password (OTP) as an integer in the range [0, 10^digits)
    HMAC_CPP_API int get_hotp_code(const void* key_ptr, size_t key_len, uint64_t counter, int digits = 6, TypeHash hash_type = TypeHash::SHA1);

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

    /// \brief Compute HOTP code using secure buffer key.
    /// \param key Secret key bytes.
    /// \param counter Moving counter.
    /// \param digits Number of digits in OTP.
    /// \param hash_type Hash function to use.
    /// \return One-Time Password.
    inline int get_hotp_code(const secure_buffer<uint8_t>& key, uint64_t counter, int digits = 6, TypeHash hash_type = TypeHash::SHA1) {
        return get_hotp_code(key.data(), key.size(), counter, digits, hash_type);
    }

    /// \brief Computes HOTP code from a std::string key interpreted as raw bytes
    /// \param key Secret key as a binary string (each character is a byte)
    /// \param counter 64-bit moving counter (monotonically increasing)
    /// \param digits Desired number of digits in the OTP (typically 6–8, max 9)
    /// \param hash_type Hash function to use (SHA1, SHA256, SHA512). Default is SHA1
    /// \return One-Time Password (OTP) as an integer in the range [0, 10^digits)
    /// \deprecated Use overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline int get_hotp_code(const std::string& key, uint64_t counter, int digits = 6, TypeHash hash_type = TypeHash::SHA1) {
        return get_hotp_code(key.data(), key.size(), counter, digits, hash_type);
    }

    namespace detail {
        /// \brief Computes HOTP code from a precomputed HMAC digest
        /// \param hmac_result HMAC digest bytes
        /// \param digits Desired number of digits in the OTP (1-9)
        /// \return One-Time Password (OTP) as an integer
        /// \throws std::runtime_error if the digest is too short for dynamic truncation
        HMAC_CPP_API int hotp_from_digest(const std::vector<uint8_t>& hmac_result, int digits);
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
    HMAC_CPP_API int get_totp_code_at(
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

    /// \brief Compute TOTP code for timestamp using secure buffer key.
    /// \param key Secret key bytes.
    /// \param timestamp UNIX timestamp in seconds.
    /// \param period Time step in seconds.
    /// \param digits Number of digits in OTP.
    /// \param hash_type Hash function to use.
    /// \return TOTP code.
    inline int get_totp_code_at(
            const secure_buffer<uint8_t>& key,
            uint64_t timestamp,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1) {
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
    /// \deprecated Use overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
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
    HMAC_CPP_API int get_totp_code(
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

    /// \brief Compute current TOTP code using secure buffer key.
    /// \param key Secret key bytes.
    /// \param period Time step in seconds.
    /// \param digits Number of digits in OTP.
    /// \param hash_type Hash function to use.
    /// \return TOTP code.
    inline int get_totp_code(const secure_buffer<uint8_t>& key, int period = 30, int digits = 6, TypeHash hash_type = TypeHash::SHA1) {
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
    /// \deprecated Use overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
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
    HMAC_CPP_API bool is_totp_token_valid(
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
    /// \param key Secret key bytes
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
            const secure_buffer<uint8_t>& key,
            uint64_t timestamp,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1) {
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
    /// \deprecated Use overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
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
    HMAC_CPP_API bool is_totp_token_valid(
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
    /// \param key Secret key bytes
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
            const secure_buffer<uint8_t>& key,
            int period = 30,
            int digits = 6,
            TypeHash hash_type = TypeHash::SHA1) {
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
    /// \deprecated Use overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
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
