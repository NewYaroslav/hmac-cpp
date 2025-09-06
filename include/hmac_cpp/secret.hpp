#ifndef HMAC_CPP_SECRET_HPP_INCLUDED
#define HMAC_CPP_SECRET_HPP_INCLUDED

#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <functional>
#include <cstring>

#include "hmac_cpp/hmac.hpp"
#include "hmac_cpp/hmac_utils.hpp"
#include "hmac_cpp/secure_buffer.hpp"
#include "hmac_cpp/memlock.hpp"

namespace hmac_cpp {

class secret_string {
public:
    secret_string() : nonce_(), locked_(false) {}

    explicit secret_string(const std::string& s) : nonce_(), locked_(false) { set(s); }
    explicit secret_string(const uint8_t* p, size_t n) : nonce_(), locked_(false) { set(p, n); }

    secret_string(secret_string&& other) noexcept { move_from(other); }
    secret_string& operator=(secret_string&& other) noexcept {
        if (this != &other) { clear(); move_from(other); }
        return *this;
    }

    secret_string(const secret_string&) = delete;
    secret_string& operator=(const secret_string&) = delete;

    ~secret_string() { clear(); }

    void clear() noexcept {
        if (!ct_.empty()) {
            secure_zero(ct_.data(), ct_.size());
            if (locked_) {
                unlock_pages(ct_.data(), ct_.size());
                locked_ = false;
            }
            ct_.clear();
            ct_.shrink_to_fit();
        }
        secure_zero(nonce_.data(), nonce_.size());
    }

    bool empty() const noexcept { return ct_.empty(); }
    size_t size() const noexcept { return ct_.size(); }

    void set(const std::string& s) { set(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }

    void set(const uint8_t* p, size_t n) {
        if (n > 0 && p == NULL) throw std::invalid_argument("secret_string::set: null data with non-zero length");
        clear();

        std::vector<uint8_t> rnd = hmac_cpp::random_bytes(12);
        std::copy(rnd.begin(), rnd.end(), nonce_.begin());

        ct_.assign(p, p + n);

        if (!ct_.empty()) {
            locked_ = lock_pages(ct_.data(), ct_.size());
        }

        xor_keystream_inplace(ct_.data(), ct_.size(), nonce_.data());
    }

    bool with_plaintext(const std::function<void(const uint8_t*, size_t)>& fn) const {
        std::vector<uint8_t> subkey = hmac_cpp::get_hmac(process_key().data(), process_key().size(),
                                                         nonce_.data(), nonce_.size(),
                                                         hmac_cpp::TypeHash::SHA256);
        std::vector<uint8_t> tmp(ct_);
        PageLockGuard g1(tmp.data(), tmp.size());
        PageLockGuard g2(subkey.data(), subkey.size());
        xor_keystream_inplace_with_key(tmp.data(), tmp.size(), nonce_.data(), subkey.data(), subkey.size());
        fn(tmp.data(), tmp.size());
        secure_zero(tmp.data(), tmp.size());
        secure_zero(subkey.data(), subkey.size());
        return true;
    }

    std::string reveal_copy() const {
        std::string out;
        out.resize(ct_.size());
        with_plaintext([&](const uint8_t* p, size_t n) {
            if (n) std::memcpy(&out[0], p, n);
        });
        return out;
    }

private:
    static std::array<uint8_t,32>& process_key() {
        static std::array<uint8_t,32> k = []{
            std::array<uint8_t,32> tmp{};
            std::vector<uint8_t> rnd = hmac_cpp::random_bytes(32);
            std::copy(rnd.begin(), rnd.end(), tmp.begin());
            (void)lock_pages(tmp.data(), tmp.size());
            return tmp;
        }();
        return k;
    }

    static void be32(uint8_t out[4], uint32_t v) {
        out[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
        out[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
        out[2] = static_cast<uint8_t>((v >>  8) & 0xFF);
        out[3] = static_cast<uint8_t>( v        & 0xFF);
    }

    static void xor_keystream_inplace_with_key(uint8_t* buf, size_t len,
                                               const uint8_t* nonce12,
                                               const uint8_t* subkey, size_t sublen) {
        if (!buf && len) return;
        if (!nonce12) return;
        if (!subkey || sublen != 32) return;

        uint8_t msg[16];
        std::memcpy(msg, nonce12, 12);

        size_t pos = 0;
        uint32_t ctr = 0;
        while (pos < len) {
            be32(msg + 12, ctr++);
            std::vector<uint8_t> block = hmac_cpp::get_hmac(subkey, 32, msg, sizeof(msg),
                                                            hmac_cpp::TypeHash::SHA256);
            const size_t take = (len - pos < block.size()) ? (len - pos) : block.size();
            for (size_t i = 0; i < take; ++i) buf[pos + i] ^= block[i];
            pos += take;
            secure_zero(block.data(), block.size());
        }
        secure_zero(msg, sizeof(msg));
    }

    void xor_keystream_inplace(uint8_t* buf, size_t len, const uint8_t* nonce12) const {
        std::vector<uint8_t> subkey = hmac_cpp::get_hmac(process_key().data(), process_key().size(),
                                                         nonce12, 12, hmac_cpp::TypeHash::SHA256);
        xor_keystream_inplace_with_key(buf, len, nonce12, subkey.data(), subkey.size());
        secure_zero(subkey.data(), subkey.size());
    }

    void move_from(secret_string& other) noexcept {
        ct_     = std::move(other.ct_);
        nonce_  = other.nonce_;
        locked_ = other.locked_;
        other.locked_ = false;
        secure_zero(other.nonce_.data(), other.nonce_.size());
    }

private:
    std::vector<uint8_t>   ct_;
    std::array<uint8_t,12> nonce_;
    bool                   locked_;
};

} // namespace hmac_cpp

#endif // HMAC_CPP_SECRET_HPP_INCLUDED
