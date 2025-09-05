#include <algorithm>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include "hmac_cpp/hmac.hpp"
#include "hmac_cpp/secure_buffer.hpp"

namespace hmac_cpp {

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

        secure_buffer<uint8_t> key(block_size);
        if (key_len > block_size) {
            auto hashed = get_hash(key_ptr, key_len, type);
            std::copy(hashed.begin(), hashed.end(), key.begin());
            if (hashed.size() < block_size)
                std::fill(key.begin() + hashed.size(), key.end(), 0);
            secure_zero(hashed.data(), hashed.size());
        } else {
            std::memcpy(key.data(), key_ptr, key_len);
            if (key_len < block_size)
                std::fill(key.begin() + key_len, key.end(), 0);
        }

        secure_buffer<uint8_t> ikeypad(block_size);
        secure_buffer<uint8_t> okeypad(block_size);
        for (size_t i = 0; i < block_size; ++i) {
            const uint8_t k = key[i];
            ikeypad[i] = k ^ 0x36;
            okeypad[i] = k ^ 0x5c;
        }

        if (msg_len > SIZE_MAX - block_size)
            throw std::overflow_error("msg_len + block_size overflow");
        secure_buffer<uint8_t> inner_data(block_size + msg_len);
        std::copy(ikeypad.begin(), ikeypad.end(), inner_data.begin());
        std::memcpy(inner_data.data() + block_size, msg_ptr, msg_len);
        secure_buffer<uint8_t> inner_hash(std::move(get_hash(inner_data.data(), inner_data.size(), type)));

        if (digest_size > SIZE_MAX - block_size)
            throw std::overflow_error("digest_size + block_size overflow");
        secure_buffer<uint8_t> outer_data(block_size + digest_size);
        std::copy(okeypad.begin(), okeypad.end(), outer_data.begin());
        std::copy(inner_hash.begin(), inner_hash.end(), outer_data.begin() + block_size);

        auto result = get_hash(outer_data.data(), outer_data.size(), type);

        secure_zero(key.data(), key.size());
        secure_zero(ikeypad.data(), ikeypad.size());
        secure_zero(okeypad.data(), okeypad.size());
        secure_zero(inner_data.data(), inner_data.size());
        secure_zero(inner_hash.data(), inner_hash.size());
        secure_zero(outer_data.data(), outer_data.size());

        return result;
    }

    std::string get_hmac(const std::vector<uint8_t>& key_input, const std::string &msg, TypeHash type, bool is_hex, bool is_upper) {
        auto hmac_vec = get_hmac(key_input.data(), key_input.size(), msg.data(), msg.size(), type);
        std::string out(reinterpret_cast<const char*>(hmac_vec.data()), hmac_vec.size());
        secure_zero(hmac_vec.data(), hmac_vec.size());
        return is_hex ? to_hex(out, is_upper) : out;
    }
}
