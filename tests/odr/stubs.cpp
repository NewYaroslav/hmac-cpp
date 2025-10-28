#include <cstring>
#include <cstddef>

extern "C" int memset_s(void* dest, size_t destsz, int ch, size_t count) {
    (void)destsz;
    std::memset(dest, ch, count);
    return 0;
}

extern "C" void explicit_bzero(void* dest, size_t count) {
    std::memset(dest, 0, count);
}