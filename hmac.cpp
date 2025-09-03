#include <algorithm>
#include <stdexcept>
#include "hmac.hpp"

namespace hmac {

    std::string to_hex(const std::string& input, bool is_upper) {
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

    std::string get_hash(const std::string &input, TypeHash type) {
        switch(type) {
            case TypeHash::SHA1: {
                uint8_t digest[hmac_hash::SHA1::DIGEST_SIZE];
                std::fill(digest, digest + hmac_hash::SHA1::DIGEST_SIZE, '\0');
                hmac_hash::SHA1 ctx = hmac_hash::SHA1();
                ctx.init();
                ctx.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
                ctx.finish(digest);
                return std::string((const char*)digest, hmac_hash::SHA1::DIGEST_SIZE);
            }
            case TypeHash::SHA256: {
                uint8_t digest[hmac_hash::SHA256::DIGEST_SIZE];
                std::fill(digest, digest + hmac_hash::SHA256::DIGEST_SIZE, '\0');
                hmac_hash::SHA256 ctx = hmac_hash::SHA256();
                ctx.init();
                ctx.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
                ctx.finish(digest);
                return std::string((const char*)digest, hmac_hash::SHA256::DIGEST_SIZE);
            }
            case TypeHash::SHA512: {
                uint8_t digest[hmac_hash::SHA512::DIGEST_SIZE];
                std::fill(digest, digest + hmac_hash::SHA512::DIGEST_SIZE, '\0');
                hmac_hash::SHA512 ctx = hmac_hash::SHA512();
                ctx.init();
                ctx.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
                ctx.finish(digest);
                return std::string((const char*)digest, hmac_hash::SHA512::DIGEST_SIZE);
            }
            default:
                throw std::invalid_argument("Unsupported hash type");
        };
    }

    std::vector<uint8_t> get_hash(const void* data, size_t length, TypeHash type) {
        switch(type) {
            case TypeHash::SHA1: {
                std::vector<uint8_t> digest(hmac_hash::SHA1::DIGEST_SIZE);
                hmac_hash::SHA1 ctx;
                ctx.init();
                ctx.update(reinterpret_cast<const uint8_t*>(data), length);
                ctx.finish(digest.data());
                return digest;
            }
            case TypeHash::SHA256: {
                std::vector<uint8_t> digest(hmac_hash::SHA256::DIGEST_SIZE);
                hmac_hash::SHA256 ctx;
                ctx.init();
                ctx.update(reinterpret_cast<const uint8_t*>(data), length);
                ctx.finish(digest.data());
                return digest;
            }
            case TypeHash::SHA512: {
                std::vector<uint8_t> digest(hmac_hash::SHA512::DIGEST_SIZE);
                hmac_hash::SHA512 ctx;
                ctx.init();
                ctx.update(reinterpret_cast<const uint8_t*>(data), length);
                ctx.finish(digest.data());
                return digest;
            }
            default:
                throw std::invalid_argument("Unsupported hash type");
        }
    }

    std::vector<uint8_t> get_hmac(const void* key_ptr, size_t key_len, const void* msg_ptr, size_t msg_len, TypeHash type) {
        if ((key_len > 0 && key_ptr == nullptr) || (msg_len > 0 && msg_ptr == nullptr))
            throw std::invalid_argument("Null pointer with non-zero length");
        size_t block_size = 0;
        size_t digest_size = 0;

        switch (type) {
            case TypeHash::SHA1:
                block_size = hmac_hash::SHA1::BLOCK_SIZE;
                digest_size = hmac_hash::SHA1::DIGEST_SIZE;
                break;
            case TypeHash::SHA256:
                block_size = hmac_hash::SHA256::SHA224_256_BLOCK_SIZE;
                digest_size = hmac_hash::SHA256::DIGEST_SIZE;
                break;
            case TypeHash::SHA512:
                block_size = hmac_hash::SHA512::SHA384_512_BLOCK_SIZE;
                digest_size = hmac_hash::SHA512::DIGEST_SIZE;
                break;
            default:
                throw std::invalid_argument("Unsupported hash type");
        }

        // Step 1: Normalize key
        std::vector<uint8_t> key(reinterpret_cast<const uint8_t*>(key_ptr), reinterpret_cast<const uint8_t*>(key_ptr) + key_len);
        if (key.size() > block_size)
            key = get_hash(key.data(), key.size(), type);
        if (key.size() < block_size)
            key.resize(block_size, 0);

        // Step 2: Create ipad and opad in one pass
        std::vector<uint8_t> ikeypad(block_size);
        std::vector<uint8_t> okeypad(block_size);
        for (size_t i = 0; i < block_size; ++i) {
            const uint8_t k = key[i];
            ikeypad[i] = k ^ 0x36;
            okeypad[i] = k ^ 0x5c;
        }

        // Step 3: Compute inner hash
        std::vector<uint8_t> inner_data;
        inner_data.reserve(block_size + msg_len);
        inner_data.insert(inner_data.end(), ikeypad.begin(), ikeypad.end());
        inner_data.insert(inner_data.end(), reinterpret_cast<const uint8_t*>(msg_ptr), reinterpret_cast<const uint8_t*>(msg_ptr) + msg_len);
        std::vector<uint8_t> inner_hash = get_hash(inner_data.data(), inner_data.size(), type);

        // Step 4: Compute final HMAC
        std::vector<uint8_t> outer_data;
        outer_data.reserve(block_size + digest_size);
        outer_data.insert(outer_data.end(), okeypad.begin(), okeypad.end());
        outer_data.insert(outer_data.end(), inner_hash.begin(), inner_hash.end());

        return get_hash(outer_data.data(), outer_data.size(), type);
    }

    std::string get_hmac(const std::string& key_input, const std::string &msg, TypeHash type, bool is_hex, bool is_upper) {
        size_t block_size = 0;
        switch(type) {
        case TypeHash::SHA1:
            block_size = hmac_hash::SHA1::BLOCK_SIZE;
            break;
        case TypeHash::SHA256:
            block_size = hmac_hash::SHA256::SHA224_256_BLOCK_SIZE;
            break;
        case TypeHash::SHA512:
            block_size = hmac_hash::SHA512::SHA384_512_BLOCK_SIZE;
            break;
        default:
            throw std::invalid_argument("Unsupported hash type");
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
