#ifndef HMAC_CPP_MEMLOCK_HPP_INCLUDED
#define HMAC_CPP_MEMLOCK_HPP_INCLUDED

#include <cstddef>
#include "hmac_cpp/api.hpp"

namespace hmac_cpp {

// Pin memory pages in RAM. Returns true on success (best-effort).
HMAC_CPP_API bool lock_pages(void* ptr, size_t len) noexcept;

// Unlock previously pinned pages. Returns true on success.
HMAC_CPP_API bool unlock_pages(void* ptr, size_t len) noexcept;

// RAII-guard for temporary buffers.
struct PageLockGuard {
    void*  p;
    size_t n;
    bool   locked;
    PageLockGuard(void* ptr, size_t len) noexcept
        : p(ptr), n(len), locked(lock_pages(ptr, len)) {}
    ~PageLockGuard() { if (locked) unlock_pages(p, n); }
    PageLockGuard(const PageLockGuard&) = delete;
    PageLockGuard& operator=(const PageLockGuard&) = delete;
};

} // namespace hmac_cpp

#endif // HMAC_CPP_MEMLOCK_HPP_INCLUDED
