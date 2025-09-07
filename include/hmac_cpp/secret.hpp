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

/// \brief Best-effort in-memory obfuscation for sensitive strings.
///
/// The plaintext is encrypted with a per-instance random nonce using
/// HMAC-SHA256 as a stream cipher keyed by a process-wide secret stored in
/// locked memory. The class aims to reduce accidental exposure but does not
/// protect against an attacker with full access to the process memory. Each
/// instance uses a unique nonce and the class itself is not thread safe.
/// Memory locking is best-effort and may fail without required privileges.
class secret_string {
public:
    secret_string() : nonce_(), locked_(false) {}

    explicit secret_string(const std::string& s) : nonce_(), locked_(false) { set(s); }
    explicit secret_string(const uint8_t* p, size_t n) : nonce_(), locked_(false) { set(p, n); }
    explicit secret_string(const secure_buffer<uint8_t>& s) : nonce_(), locked_(false) { set(s); }
    explicit secret_string(secure_buffer<uint8_t>&& s) : nonce_(), locked_(false) { set(std::move(s)); }

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
        }
        secure_zero(nonce_.data(), nonce_.size());
    }

    bool empty() const noexcept { return ct_.empty(); }
    size_t size() const noexcept { return ct_.size(); }

    void set(const std::string& s) { set(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }
    void set(const secure_buffer<uint8_t>& s) { set(s.data(), s.size()); }
    void set(secure_buffer<uint8_t>&& s) {
        set(s.data(), s.size());
        if (s.size()) {
            secure_zero(s.data(), s.size());
        }
    }

    void set(const uint8_t* p, size_t n) {
        if (n && !p) throw std::invalid_argument("secret_string::set: null data");
        clear();

        auto rnd = hmac_cpp::random_bytes(12);
        std::copy(rnd.begin(), rnd.end(), nonce_.begin());

        ct_.resize(n);
        if (n) locked_ = lock_pages(ct_.data(), ct_.size());

        xor_keystream_copy_inplace(ct_.data(), p, n, nonce_.data());
    }

    bool with_plaintext(const std::function<void(const uint8_t*, size_t)>& fn) const {
        uint8_t subkey[32];
        {
            HmacContext ctx(hmac_cpp::TypeHash::SHA256);
            auto& pk = process_key();
            ctx.init(pk.data(), pk.size());
            ctx.update(nonce_.data(), nonce_.size());
            ctx.final(subkey, sizeof subkey);
        }
        std::vector<uint8_t> tmp(ct_);
        PageLockGuard g1(tmp.data(), tmp.size());
        xor_keystream_inplace_with_key(tmp.data(), tmp.size(), nonce_.data(), subkey, sizeof subkey);
        fn(tmp.data(), tmp.size());
        secure_zero(tmp.data(), tmp.size());
        secure_zero(subkey, sizeof subkey);
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

    void rekey_runtime() {
        if (ct_.empty()) return;

        uint8_t oldk[32], newk[32];
        auto& pk = process_key();
        {
            HmacContext ctx(hmac_cpp::TypeHash::SHA256);
            ctx.init(pk.data(), pk.size());
            ctx.update(nonce_.data(), nonce_.size());
            ctx.final(oldk, sizeof oldk);
        }

        {
            auto rnd = hmac_cpp::random_bytes(pk.size());
            std::copy(rnd.begin(), rnd.end(), pk.begin());
        }

        {
            HmacContext ctx(hmac_cpp::TypeHash::SHA256);
            ctx.init(pk.data(), pk.size());
            ctx.update(nonce_.data(), nonce_.size());
            ctx.final(newk, sizeof newk);
        }

        uint8_t msg[16]; std::memcpy(msg, nonce_.data(), 12);
        uint32_t ctr = 0;
        uint8_t oldb[32], newb[32];

        size_t pos = 0;
        while (pos < ct_.size()) {
            be32(msg + 12, ctr++);

            HmacContext c1(hmac_cpp::TypeHash::SHA256);
            c1.init(oldk, sizeof oldk);
            c1.update(msg, sizeof msg);
            c1.final(oldb, sizeof oldb);

            HmacContext c2(hmac_cpp::TypeHash::SHA256);
            c2.init(newk, sizeof newk);
            c2.update(msg, sizeof msg);
            c2.final(newb, sizeof newb);

            const size_t take = (ct_.size() - pos < sizeof oldb) ? (ct_.size() - pos) : sizeof oldb;
            for (size_t i = 0; i < take; ++i) ct_[pos + i] ^= (oldb[i] ^ newb[i]);
            pos += take;
        }

        secure_zero(oldk, sizeof oldk);
        secure_zero(newk, sizeof newk);
        secure_zero(oldb, sizeof oldb);
        secure_zero(newb, sizeof newb);
        secure_zero(msg, sizeof msg);
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
        if (len && (!buf || !nonce12 || !subkey || sublen != 32)) return;

        uint8_t msg[16]; std::memcpy(msg, nonce12, 12);
        uint32_t ctr = 0;
        uint8_t block[32];

        size_t pos = 0;
        while (pos < len) {
            be32(msg + 12, ctr++);

            HmacContext ctx(hmac_cpp::TypeHash::SHA256);
            ctx.init(subkey, 32);
            ctx.update(msg, sizeof msg);
            ctx.final(block, sizeof block);

            const size_t take = (len - pos < sizeof block) ? (len - pos) : sizeof block;
            for (size_t i = 0; i < take; ++i) buf[pos + i] ^= block[i];
            pos += take;
        }
        secure_zero(block, sizeof block);
        secure_zero(msg, sizeof msg);
    }

    void xor_keystream_inplace(uint8_t* buf, size_t len, const uint8_t* nonce12) const {
        uint8_t subkey[32];
        {
            HmacContext ctx(hmac_cpp::TypeHash::SHA256);
            auto& pk = process_key();
            ctx.init(pk.data(), pk.size());
            ctx.update(nonce12, 12);
            ctx.final(subkey, sizeof subkey);
        }
        xor_keystream_inplace_with_key(buf, len, nonce12, subkey, sizeof subkey);
        secure_zero(subkey, sizeof subkey);
    }

    void xor_keystream_copy_inplace(uint8_t* out, const uint8_t* in, size_t len, const uint8_t* nonce12) const {
        uint8_t subkey[32];
        {
            HmacContext ctx(hmac_cpp::TypeHash::SHA256);
            auto& pk = process_key();
            ctx.init(pk.data(), pk.size());
            ctx.update(nonce12, 12);
            ctx.final(subkey, sizeof subkey);
        }

        uint8_t msg[16]; std::memcpy(msg, nonce12, 12);
        uint32_t ctr = 0;
        uint8_t block[32];

        size_t pos = 0;
        while (pos < len) {
            be32(msg + 12, ctr++);

            HmacContext ctx(hmac_cpp::TypeHash::SHA256);
            ctx.init(subkey, 32);
            ctx.update(msg, sizeof msg);
            ctx.final(block, sizeof block);

            const size_t take = (len - pos < sizeof block) ? (len - pos) : sizeof block;
            for (size_t i = 0; i < take; ++i) out[pos + i] = in[pos + i] ^ block[i];
            pos += take;
        }

        secure_zero(block, sizeof block);
        secure_zero(msg, sizeof msg);
        secure_zero(subkey, sizeof subkey);
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
