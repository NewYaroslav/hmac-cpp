#include <array>
#include <cstddef>

#undef __STDC_WANT_LIB_EXT1__
#undef __STDC_LIB_EXT1__
#undef HAVE_EXPLICIT_BZERO

#include <hmac_cpp/secure_buffer.hpp>

namespace {
constexpr int detect_branch() {
#if defined(__STDC_LIB_EXT1__)
    return 1;
#elif defined(HAVE_EXPLICIT_BZERO)
    return 2;
#else
    return 3;
#endif
}
}

extern "C" int secure_zero_branch_manual() {
    std::array<unsigned char, 8> buffer{{0xBB}};
    hmac_cpp::secure_zero(buffer.data(), buffer.size());
    return detect_branch();
}