#include <array>
#include <algorithm>
#include <cstddef>

extern "C" int memset_s(void* dest, size_t destsz, int ch, size_t count);

#define __STDC_WANT_LIB_EXT1__ 1
#define __STDC_LIB_EXT1__ 1
#undef HAVE_EXPLICIT_BZERO

#include <hmac_cpp/secure_buffer.hpp>

extern "C" bool secure_zero_memset_s_branch() {
    std::array<unsigned char, 8> buffer{};
    buffer.fill(0xAA);

    hmac_cpp::secure_zero(buffer.data(), buffer.size());

    return std::all_of(buffer.begin(), buffer.end(), [](unsigned char value) {
        return value == 0;
    });
}