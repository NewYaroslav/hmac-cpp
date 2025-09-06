#include "hmac_cpp/memlock.hpp"

#if defined(HMAC_CPP_ENABLE_MLOCK)

#if defined(_WIN32)
#include <windows.h>
namespace {
inline bool do_lock(void* p, size_t n)  { return VirtualLock(p, n) != 0; }
inline bool do_unlock(void* p, size_t n){ return VirtualUnlock(p, n) != 0; }
}
namespace hmac_cpp {
bool lock_pages(void* ptr, size_t len) noexcept   { return (ptr && len) ? do_lock(ptr, len)   : false; }
bool unlock_pages(void* ptr, size_t len) noexcept { return (ptr && len) ? do_unlock(ptr, len) : false; }
}

#else
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

namespace {
inline void* page_align(void* p, size_t len, size_t& out_len) {
    if (!p || !len) { out_len = 0; return p; }
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) { out_len = 0; return p; }
    uintptr_t addr = reinterpret_cast<uintptr_t>(p);
    uintptr_t start = addr & ~static_cast<uintptr_t>(ps - 1);
    uintptr_t end   = (addr + len + ps - 1) & ~static_cast<uintptr_t>(ps - 1);
    out_len = static_cast<size_t>(end - start);
    return reinterpret_cast<void*>(start);
}
}

namespace hmac_cpp {
bool lock_pages(void* ptr, size_t len) noexcept {
    if (!ptr || !len) return false;
    size_t alen = 0;
    void*  aptr = page_align(ptr, len, alen);
    if (!aptr || !alen) return false;
    return ::mlock(aptr, alen) == 0;
}
bool unlock_pages(void* ptr, size_t len) noexcept {
    if (!ptr || !len) return false;
    size_t alen = 0;
    void*  aptr = page_align(ptr, len, alen);
    if (!aptr || !alen) return false;
    return ::munlock(aptr, alen) == 0;
}
}

#endif

#else // !HMAC_CPP_ENABLE_MLOCK

namespace hmac_cpp {
bool lock_pages(void* ptr, size_t len) noexcept   { (void)ptr; (void)len; return false; }
bool unlock_pages(void* ptr, size_t len) noexcept { (void)ptr; (void)len; return false; }
}

#endif // HMAC_CPP_ENABLE_MLOCK
