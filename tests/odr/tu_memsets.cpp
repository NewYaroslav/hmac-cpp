#include <array>
#include <cstddef>

extern "C" int memset_s(void* dest, size_t destsz, int ch, size_t count);

#define __STDC_WANT_LIB_EXT1__ 1
#define __STDC_LIB_EXT1__ 1
#undef HAVE_EXPLICIT_BZERO

#include <hmac_cpp/secure_buffer.hpp>

namespace {
constexpr int detect_branch() {
#if defined(__STDC_LIB_EXT1__)
    return 1; // secure_zero uses memset_s branch
#elif defined(HAVE_EXPLICIT_BZERO)
    return 2; // secure_zero uses explicit_bzero branch
#else
    return 3; // fallback manual zeroing
#endif
}
}

extern "C" int secure_zero_branch_memsets() {
    std::array<unsigned char, 8> buffer{{0xAA}};
    hmac_cpp::secure_zero(buffer.data(), buffer.size());
    return detect_branch();
}