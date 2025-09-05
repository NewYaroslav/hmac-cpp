#ifndef _HMAC_HPP_INCLUDED
#define _HMAC_HPP_INCLUDED

#include <cstdint>
#include <string>
#include <vector>
#include "api.hpp"
#include "sha1.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "secure_buffer.hpp"

namespace hmac_cpp {

    /// \brief Type of the hash function used
    enum class TypeHash {
        SHA1,   ///< Use SHA1
        SHA256, ///< Use SHA256
        SHA512, ///< Use SHA512
    };

    /// \brief Converts a string to hexadecimal format
    /// \param input Input string
    /// \param is_upper Flag for uppercase hex
    /// \return Hexadecimal string
    HMAC_CPP_API std::string to_hex(const std::string& input, bool is_upper = false);

    /// \brief Computes hash of the input string
    /// \param input Input string
    /// \param type Hash function type
    /// \return Hash result
    HMAC_CPP_API std::string get_hash(const std::string &input, TypeHash type);
    
    /// \brief Computes a hash of a raw buffer using the selected hash function
    /// \param data Pointer to input data
    /// \param length Length of the input data
    /// \param type Hash function type
    /// \return Binary hash result as std::vector<uint8_t>
    HMAC_CPP_API std::vector<uint8_t> get_hash(const void* data, size_t length, TypeHash type);
    
    /// \brief Computes a hash of a vector using the selected hash function.
    /// \tparam T Type of the vector element (char or uint8_t).
    /// \param input Input vector.
    /// \param type Hash function type.
    /// \return Binary hash result as std::vector<uint8_t>
    template<typename T>
    std::vector<uint8_t> get_hash(const std::vector<T>& input, TypeHash type) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "get_hash(vector<T>) only supports vector<char> or vector<uint8_t>");

        return get_hash(input.data(), input.size(), type);
    }

    /// \brief Streaming HMAC computation context.
    class HMAC_CPP_API HmacContext {
    public:
        explicit HmacContext(TypeHash type) : type_(type), block_size_(0), digest_size_(0) {}

        /// \brief Initializes the context with a secret key.
        /// \param key_ptr Pointer to the key buffer; must be non-null if key_len > 0
        /// \param key_len Length of the key in bytes
        void init(const void* key_ptr, size_t key_len);

        /// \brief Updates the HMAC with message data.
        /// \param data_ptr Pointer to the message buffer; must be non-null if data_len > 0
        /// \param data_len Length of the message in bytes
        void update(const void* data_ptr, size_t data_len);

        /// \brief Finalizes the HMAC and writes the result to the provided buffer.
        /// \param out_ptr Output buffer for the HMAC result
        /// \param out_len Length of the output buffer; must be at least the digest size
        void final(uint8_t* out_ptr, size_t out_len);

    private:
        TypeHash type_;
        size_t block_size_;
        size_t digest_size_;
        secure_buffer<uint8_t> okeypad_;
        hmac_hash::SHA1 sha1_;
        hmac_hash::SHA256 sha256_;
        hmac_hash::SHA512 sha512_;
    };

    /// \brief Computes HMAC for raw binary data using the specified hash function.
    /// \param key_ptr Pointer to the key buffer; must be non-null if key_len > 0
    /// \param key_len Length of the key in bytes
    /// \param msg_ptr Pointer to the message buffer; must be non-null if msg_len > 0
    /// \param msg_len Length of the message in bytes
    /// \param type Hash function type
    /// \return HMAC result as a vector of bytes
    /// \throws std::invalid_argument If any pointer is null while the corresponding length is non-zero
    HMAC_CPP_API std::vector<uint8_t> get_hmac(const void* key_ptr, size_t key_len, const void* msg_ptr, size_t msg_len, TypeHash type);

    /// \brief Computes HMAC from key and message byte vectors using the specified hash function
    /// \tparam T Byte type: must be either char or uint8_t
    /// \param key Key as a vector
    /// \param msg Message as a vector
    /// \param type Hash function type
    /// \return HMAC result as a vector of bytes
    template<typename T>
    std::vector<uint8_t> get_hmac(const std::vector<T>& key, const std::vector<T>& msg, TypeHash type) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "get_hmac(vector<T>) only supports vector<char> or vector<uint8_t>");

        return get_hmac(key.data(), key.size(), msg.data(), msg.size(), type);
    }
    
    /// \brief Computes HMAC
    /// \param key Secret key as byte vector
    /// \param msg Message
    /// \param type Hash function type
    /// \param is_hex Return result in hex format
    /// \param is_upper Use uppercase hex
    /// \return HMAC result
    HMAC_CPP_API std::string get_hmac(const std::vector<uint8_t>& key, const std::string &msg, TypeHash type, bool is_hex = true, bool is_upper = false);

    /// \brief Computes HMAC from secure_buffer key
    inline std::string get_hmac(const secure_buffer<uint8_t>& key, const std::string &msg, TypeHash type, bool is_hex = true, bool is_upper = false) {
        return get_hmac(std::vector<uint8_t>(key.begin(), key.end()), msg, type, is_hex, is_upper);
    }

    /// \deprecated Prefer overloads that accept std::vector<uint8_t> or secure_buffer.
    HMACCPP_DEPRECATED("use std::vector<uint8_t> or secure_buffer overload")
    inline std::string get_hmac(const std::string& key_input, const std::string &msg, TypeHash type, bool is_hex = true, bool is_upper = false) {
        return get_hmac(std::vector<uint8_t>(key_input.begin(), key_input.end()), msg, type, is_hex, is_upper);
    }
}
namespace hmac = hmac_cpp;

#endif // _HMAC_HPP_INCLUDED
