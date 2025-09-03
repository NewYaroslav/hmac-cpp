#ifndef _HMAC_HPP_INCLUDED
#define _HMAC_HPP_INCLUDED

#include <cstdint>
#include "sha1.hpp"
#include "sha256.hpp"
#include "sha512.hpp"

namespace hmac {

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
    std::string to_hex(const std::string& input, bool is_upper = false);

    /// \brief Computes hash of the input string
    /// \param input Input string
    /// \param type Hash function type
    /// \return Hash result
    std::string get_hash(const std::string &input, TypeHash type);
    
    /// \brief Computes a hash of a raw buffer using the selected hash function
    /// \param data Pointer to input data
    /// \param length Length of the input data
    /// \param type Hash function type
    /// \return Binary hash result as std::vector<uint8_t>
    std::vector<uint8_t> get_hash(const void* data, size_t length, TypeHash type);
    
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

    /// \brief Computes HMAC for raw binary data using the specified hash function.
    /// \param key_ptr Pointer to the key buffer; must be non-null if key_len > 0
    /// \param key_len Length of the key in bytes
    /// \param msg_ptr Pointer to the message buffer; must be non-null if msg_len > 0
    /// \param msg_len Length of the message in bytes
    /// \param type Hash function type
    /// \return HMAC result as a vector of bytes
    /// \throws std::invalid_argument If any pointer is null while the corresponding length is non-zero
    std::vector<uint8_t> get_hmac(const void* key_ptr, size_t key_len, const void* msg_ptr, size_t msg_len, TypeHash type);

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
    /// \param key Secret key
    /// \param msg Message
    /// \param type Hash function type
    /// \param is_hex Return result in hex format
    /// \param is_upper Use uppercase hex
    /// \return HMAC result
    std::string get_hmac(const std::string& key_input, const std::string &msg, TypeHash type, bool is_hex = true, bool is_upper = false);
}

#endif // _HMAC_HPP_INCLUDED
