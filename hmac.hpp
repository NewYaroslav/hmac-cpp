#ifndef _HMAC_HPP_INCLUDED
#define _HMAC_HPP_INCLUDED

#include "sha256.hpp"
#include "sha512.hpp"
#include <string>

namespace hmac {

    /// \brief Type of the hash function used
    enum class TypeHash {
        SHA256 = 0, ///< Use SHA256
        SHA512 = 1, ///< Use SHA512
    };

    /// \brief Converts a string to hexadecimal format
    /// \param input Input string
    /// \param is_upper Flag for uppercase hex
    /// \return Hexadecimal string
    std::string to_hex(const std::string& input, bool is_upper = false) {
        static const char *lut = "0123456789abcdef0123456789ABCDEF";
        const char *symbol = is_upper ? lut + 16 : lut;
        const size_t length = input.size();
        std::string output;
        output.reserve(2 * length);
        for (size_t i = 0; i < length; ++i) {
            const uint8_t ch = static_cast<uint8_t>(input[i]);
            output.push_back(symbol[ch >> 4]);
            output.push_back(symbol[ch & 0x0F]);
        }
        return output;
    }

    /// \brief Computes hash of the input string
    /// \param input Input string
    /// \param type Hash function type
    /// \return Hash result
    std::string get_hash(const std::string &input, TypeHash type) {
        switch(type) {
            case TypeHash::SHA256: {
                uint8_t digest[hmac_hash::SHA256::DIGEST_SIZE];
                std::fill(digest, digest + hmac_hash::SHA256::DIGEST_SIZE, '\0');
                hmac_hash::SHA256 ctx = hmac_hash::SHA256();
                ctx.init();
                ctx.update((uint8_t*)input.c_str(), input.size());
                ctx.final(digest);
                return std::string((const char*)digest, hmac_hash::SHA256::DIGEST_SIZE);
            }
            case TypeHash::SHA512: {
                uint8_t digest[hmac_hash::SHA512::DIGEST_SIZE];
                std::fill(digest, digest + hmac_hash::SHA512::DIGEST_SIZE, '\0');
                hmac_hash::SHA512 ctx = hmac_hash::SHA512();
                ctx.init();
                ctx.update((uint8_t*)input.c_str(), input.size());
                ctx.final(digest);
                return std::string((const char*)digest, hmac_hash::SHA512::DIGEST_SIZE);
            }
            default: break;
        };
        return std::string();
    }

    /// \brief Computes HMAC
    /// \param key Secret key
    /// \param msg Message
    /// \param type Hash function type
    /// \param is_hex Return result in hex format
    /// \param is_upper Use uppercase hex
    /// \return HMAC result
    std::string get_hmac(const std::string& key_input, const std::string &msg, TypeHash type, bool is_hex = true, bool is_upper = false) {
        size_t block_size = 0;
        switch(type) {
        case TypeHash::SHA256:
            block_size = hmac_hash::SHA256::SHA224_256_BLOCK_SIZE;
            break;
        case TypeHash::SHA512:
            block_size = hmac_hash::SHA512::SHA384_512_BLOCK_SIZE;
            break;
        default:
            return std::string();
        };

        std::string key = key_input;
        
        if(key.size() > block_size) {
            /* If key length > block size, hash it and pad with zeros to block size */
            key = get_hash(key, type);
        }
        if(key.size() < block_size) {
            /* Pad key with zeros if it's shorter than block size */
            key.resize(block_size, '\0');
        }
        
        /* If key length == block size, use it as is */
        std::string ikeypad;
        std::string okeypad;
        
        ikeypad.reserve(block_size);
        okeypad.reserve(block_size);
        
        for(size_t i = 0; i < block_size; ++i) {
            ikeypad.push_back(0x36 ^ key[i]);
            okeypad.push_back(0x5c ^ key[i]);
        }

        return is_hex 
            ? to_hex(get_hash(okeypad + get_hash(ikeypad + msg, type), type), is_upper) 
            : get_hash(okeypad + get_hash(ikeypad + msg, type), type);
    }
}

#endif // _HMAC_HPP_INCLUDED
