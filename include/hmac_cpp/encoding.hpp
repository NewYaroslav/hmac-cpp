#ifndef _HMAC_ENCODING_HPP_INCLUDED
#define _HMAC_ENCODING_HPP_INCLUDED

#include "api.hpp"
#include "secure_buffer.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace hmac_cpp {

    /// \brief Alphabet variant for Base64.
    enum class Base64Alphabet { Standard, Url }; // Standard: "+/", Url: "-_"

    // -------------------------
    // Base64 — encode / decode
    // -------------------------

    /// \brief Base64-encode a byte buffer (RFC 4648).
    /// \param data Pointer to input bytes.
    /// \param len  Number of input bytes.
    /// \param alphabet Standard ("+/") or URL-safe ("-_") alphabet.
    /// \param pad If true, append '=' padding to a multiple of 4 chars.
    /// \return Encoded string.
    HMAC_CPP_API std::string base64_encode(const uint8_t* data, size_t len,
                                           Base64Alphabet alphabet = Base64Alphabet::Standard,
                                           bool pad = true);

    /// \brief Base64-encode a vector.
    inline HMAC_CPP_API std::string base64_encode(const std::vector<uint8_t>& v,
                                     Base64Alphabet alphabet = Base64Alphabet::Standard,
                                     bool pad = true) {
        return base64_encode(v.data(), v.size(), alphabet, pad);
    }

    /// \brief Base64-encode a secure_buffer.
    inline HMAC_CPP_API std::string base64_encode(const secure_buffer<uint8_t>& v,
                                     Base64Alphabet alphabet = Base64Alphabet::Standard,
                                     bool pad = true) {
        return base64_encode(v.data(), v.size(), alphabet, pad);
    }

    /// \brief Decode a Base64 string (RFC 4648).
    /// \param in Input string (raw Base64 chars).
    /// \param out Output byte vector (overwritten).
    /// \param alphabet Standard ("+/") or URL-safe ("-_") alphabet.
    /// \param require_padding If true, input must have proper '=' padding and length % 4 == 0.
    /// \param strict If true, disallow whitespace and require '=' only in the last quartet.
    ///               If false, ignore ASCII spaces/CR/LF/TAB, allow missing padding, and
    ///               accept mixed "+/" and "-_" when \p alphabet == Url.
    /// \return true on success, false on invalid input.
    HMAC_CPP_API bool base64_decode(const std::string& in, std::vector<uint8_t>& out,
                                    Base64Alphabet alphabet = Base64Alphabet::Standard,
                                    bool require_padding = false,
                                    bool strict = true) noexcept;

    /// \brief Decode Base64 into secure_buffer.
    HMAC_CPP_API bool base64_decode(const std::string& in, secure_buffer<uint8_t>& out,
                                    Base64Alphabet alphabet = Base64Alphabet::Standard,
                                    bool require_padding = false,
                                    bool strict = true) noexcept;

    // -------------------------
    // Base32 — encode / decode
    // -------------------------

    /// \brief Base32-encode a byte buffer (RFC 4648; alphabet A–Z, 2–7).
    /// \param data Pointer to input bytes.
    /// \param len  Number of input bytes.
    /// \param pad If true, append '=' padding to a multiple of 8 chars.
    /// \return Encoded string (upper-case alphabet).
    HMAC_CPP_API std::string base32_encode(const uint8_t* data, size_t len,
                                           bool pad = true);

    /// \brief Base32-encode a vector.
    inline HMAC_CPP_API std::string base32_encode(const std::vector<uint8_t>& v, bool pad = true) {
        return base32_encode(v.data(), v.size(), pad);
    }

    /// \brief Base32-encode a secure_buffer.
    inline HMAC_CPP_API std::string base32_encode(const secure_buffer<uint8_t>& v, bool pad = true) {
        return base32_encode(v.data(), v.size(), pad);
    }

    /// \brief Decode a Base32 string (RFC 4648).
    /// \param in Input string (Base32; upper-case preferred).
    /// \param out Output byte vector (overwritten).
    /// \param require_padding If true, input must have proper '=' padding and length % 8 == 0.
    /// \param strict If true, disallow whitespace and lower-case; enforce '=' only in the last block.
    ///               If false, ignore ASCII spaces/CR/LF/TAB and accept lower-case letters.
    /// \return true on success, false on invalid input.
    HMAC_CPP_API bool base32_decode(const std::string& in, std::vector<uint8_t>& out,
                                    bool require_padding = false,
                                    bool strict = true) noexcept;

    /// \brief Decode Base32 into secure_buffer.
    HMAC_CPP_API bool base32_decode(const std::string& in, secure_buffer<uint8_t>& out,
                                    bool require_padding = false,
                                    bool strict = true) noexcept;

    // -------------------------
    // Base36 — encode / decode
    // -------------------------

    /// \brief Base36-encode a byte buffer (digits 0–9, letters A–Z).
    ///        Leading zero bytes are preserved by prefixing '0'.
    ///        Input of a single \x00 returns "0".
    /// \param data Pointer to input bytes (big-endian).
    /// \param len  Number of input bytes.
    /// \return Encoded string.
    HMAC_CPP_API std::string base36_encode(const uint8_t* data, size_t len);

    /// \brief Base36-encode a vector.
    inline HMAC_CPP_API std::string base36_encode(const std::vector<uint8_t>& v) {
        return base36_encode(v.data(), v.size());
    }

    /// \brief Base36-encode a secure_buffer.
    inline HMAC_CPP_API std::string base36_encode(const secure_buffer<uint8_t>& v) {
        return base36_encode(v.data(), v.size());
    }

    /// \brief Decode a Base36 string.
    /// \param in  Input string (case-insensitive).
    /// \param out Output byte vector (overwritten).
    /// \return true on success, false on invalid input.
    HMAC_CPP_API bool base36_decode(const std::string& in, std::vector<uint8_t>& out) noexcept;

    /// \brief Decode Base36 into secure_buffer.
    HMAC_CPP_API bool base36_decode(const std::string& in, secure_buffer<uint8_t>& out) noexcept;

} // namespace hmac_cpp

#endif // _HMAC_ENCODING_HPP_INCLUDED
