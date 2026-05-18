#include <array>
#include <algorithm>
#include <cstddef>

extern "C" void explicit_bzero(void* dest, size_t count) noexcept;

#undef __STDC_WANT_LIB_EXT1__
#undef __STDC_LIB_EXT1__
#define HAVE_EXPLICIT_BZERO 1

#include <hmac_cpp/secure_buffer.hpp>

extern "C" bool secure_zero_explicit_bzero_branch() {
    std::array<unsigned char, 8> buffer{};
    buffer.fill(0xBB);

    hmac_cpp::secure_zero(buffer.data(), buffer.size());

    return std::all_of(buffer.begin(), buffer.end(), [](unsigned char value) {
        return value == 0;
    });
}