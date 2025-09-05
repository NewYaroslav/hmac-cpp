#ifndef HMAC_CPP_SECURE_BUFFER_HPP
#define HMAC_CPP_SECURE_BUFFER_HPP

#include <cstddef>
#include <vector>
#include <type_traits>
#include <string>

// Macro to mark deprecated APIs in a compiler-portable way
#ifndef HMACCPP_DEPRECATED
#if defined(__clang__) || defined(__GNUC__)
#define HMACCPP_DEPRECATED(msg) __attribute__((deprecated(msg)))
#elif defined(_MSC_VER)
#define HMACCPP_DEPRECATED(msg) __declspec(deprecated(msg))
#else
#define HMACCPP_DEPRECATED(msg)
#endif
#endif

namespace hmac_cpp {

/// \brief Securely zeroes a memory region.
/// \param ptr Pointer to the memory to wipe.
/// \param len Number of bytes to set to zero.
inline void secure_zero(void* ptr, size_t len) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

/// \brief Vector-like buffer that zeroizes its contents on destruction.
/// \tparam T Trivial value type stored in the buffer (defaults to uint8_t).
template<class T = uint8_t>
struct secure_buffer {
    static_assert(std::is_trivial<T>::value, "secure_buffer requires trivial type");

    secure_buffer() = default;

    /// \brief Construct with n default-initialized elements.
    /// \param n Element count.
    explicit secure_buffer(size_t n) : buf(n) {}

    /// \brief Construct from vector, moving its contents.
    /// \param v Source vector.
    explicit secure_buffer(std::vector<T>&& v) : buf(std::move(v)) {}

    /// \brief Construct from std::string rvalue and zeroize the source.
    /// \param s Source string.
    template<class U = T, typename std::enable_if<std::is_same<U, uint8_t>::value, int>::type = 0>
    explicit secure_buffer(std::string&& s) : buf(s.begin(), s.end()) {
        if (!s.empty()) {
            secure_zero(&s[0], s.size());
            s.clear();
        }
    }
    /// \brief Zeroize contents on destruction.
    ~secure_buffer() { secure_zero(buf.data(), buf.size() * sizeof(T)); }

    T* data() { return buf.data(); }
    const T* data() const { return buf.data(); }
    size_t size() const { return buf.size(); }

    T& operator[](size_t i) { return buf[i]; }
    const T& operator[](size_t i) const { return buf[i]; }

    typename std::vector<T>::iterator begin() { return buf.begin(); }
    typename std::vector<T>::iterator end() { return buf.end(); }
    typename std::vector<T>::const_iterator begin() const { return buf.begin(); }
    typename std::vector<T>::const_iterator end() const { return buf.end(); }

private:
    std::vector<T> buf;
};

} // namespace hmac_cpp

#endif // HMAC_CPP_SECURE_BUFFER_HPP
