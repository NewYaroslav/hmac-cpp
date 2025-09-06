# hmac-cpp [🇷🇺 README-RU](./README-RU.md)

[![Linux](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml)
[![Windows](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml)
[![macOS](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-macOS.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-macOS.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight **C++11** library for computing **HMAC** (SHA-1/SHA-256/SHA-512), key derivation (**PBKDF2**, **HKDF**), and OTP (**HOTP**, **TOTP**). Includes optional **time-based HMAC tokens** for simple stateless use-cases and **MQL5** compatibility.

---

## 🚀 Features

* **C++11** compatible
* HMAC with **SHA1**, **SHA256**, **SHA512**
* Output as **binary** or **hex**
* **PBKDF2** (RFC 8018) — password-based key derivation
* **HKDF** (RFC 5869) — key extraction/expansion
* **OTP**:

  * **HOTP** (RFC 4226) — counter-based
  * **TOTP** (RFC 6238) — time-based
* **Time-based HMAC tokens** — lightweight, stateless HMAC(timestamp)-style tokens *(not TOTP/HOTP)*
* **MQL5 support** — adapted SHA/HMAC for MetaTrader 5
* Exported CMake package target: **`hmac_cpp::hmac_cpp`**

---

## ⚙️ Platform & Compiler Support

CI covers Linux/Windows/macOS. Tested with GCC, Clang, and MSVC; requires C++11.

---

## 🔧 Build & Installation

Examples, tests, and benchmarks are OFF by default. Enable via:

* `HMACCPP_BUILD_EXAMPLES`
* `HMACCPP_BUILD_TESTS`
* `HMACCPP_BUILD_BENCH`

### Build

```bash
cmake -B build -DHMACCPP_BUILD_EXAMPLES=ON
cmake --build build
```

### Install

```bash
cmake --install build --prefix _install
```

Install layout:

```
_install/
├─ include/hmac_cpp/
│  ├─ hmac.hpp
│  ├─ hmac_utils.hpp
│  ├─ sha1.hpp
│  ├─ sha256.hpp
│  ├─ sha512.hpp
│  └─ secure_buffer.hpp    # if included in your build
└─ lib/
   └─ libhmac_cpp.a
```

### Consume with CMake

```cmake
find_package(hmac_cpp CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE hmac_cpp::hmac_cpp)
```

### Manual compile after install

```bash
# adjust paths to your prefix
g++ example.cpp -std=c++11 -I_install/include -L_install/lib -lhmac_cpp
```

Predefined MinGW build scripts are available: `build_*.bat`.

---

## 📘 Usage

> **Note on SHA-1**: HMAC-SHA1 is supported for compatibility/OTP. Prefer HMAC-SHA256/512 for new designs.

### HMAC (string input)

```cpp
std::string get_hmac(
    const std::string& key,
    const std::string& msg,
    TypeHash type,
    bool is_hex = true,
    bool is_upper = false);
```

* `type`: `hmac::TypeHash::SHA256` / `SHA512` / `SHA1`
* Returns hex by default. For **binary** output, prefer the `std::vector<uint8_t>` overload.

**Constant-time compare** — treat lengths as public:

```cpp
bool equal = (a.size() == b.size()) && hmac::constant_time_equal(a, b);
```

**(Optional) Secure handling of string keys** — if you use `secure_buffer`:

```cpp
#include <hmac_cpp/secure_buffer.hpp>
secure_buffer key(std::move(secret_string)); // zeroizes moved-from string
auto mac = hmac::get_hmac(key, payload, hmac::TypeHash::SHA256);
```

### HMAC (raw buffer)

```cpp
std::vector<uint8_t> get_hmac(
    const void* key_ptr, size_t key_len,
    const void* msg_ptr, size_t msg_len,
    TypeHash type);
```

### HMAC (vectors)

```cpp
template<typename T>
std::vector<uint8_t> get_hmac(
    const std::vector<T>& key,
    const std::vector<T>& msg,
    TypeHash type);
// T must be char or uint8_t
```

### PBKDF2 (RFC 8018)

Derive a key from a password.

```cpp
#include <hmac_cpp/hmac_utils.hpp>
auto salt = hmac::random_bytes(16);
auto key  = hmac::pbkdf2_hmac_sha256(password, salt, iters, 32); // 32 = AES-256
```

**Recommendations**

* **Salt**: 16–32 random bytes (unique per password). Store next to ciphertext.
* **Iterations**: tune for \~100–250 ms on target hardware (e.g., desktop ≈ 600k, laptop ≈ 300k, mobile ≈ 150k; adjust).
* **Derived key length**: 32 bytes; **PRF**: HMAC-SHA256.

**Serialization example** (binary):

```
magic(4) | ver(1) | alg(1=PBKDF2-HS256) |
iter(4, BE) | salt_len(1) | salt | iv_len(1) | iv | ct_len(4, BE) | ct | tag(16)
```

See `example_pbkdf2.cpp` for an end-to-end example.

### HKDF (RFC 5869)

```cpp
std::vector<uint8_t> ikm = {/* secret material */};
std::vector<uint8_t> salt(16, 0x00);
auto prk = hmac::hkdf_extract_sha256(ikm, salt);
auto okm = hmac::hkdf_expand_sha256(prk, /*info=*/{}, /*L=*/32); // L ≤ 255*HashLen
```

### Base64 / Base32

Utility helpers for Base64 (standard or URL alphabet) and Base32.

```cpp
#include <hmac_cpp/encoding.hpp>

std::vector<uint8_t> key = {0xff, 0xee};
std::string b64 = hmac_cpp::base64_encode(key, hmac_cpp::Base64Alphabet::Url, false);
hmac_cpp::secure_buffer<uint8_t> raw;
hmac_cpp::base64_decode(b64, raw, hmac_cpp::Base64Alphabet::Url, false);
```

### 🕓 HOTP / TOTP

OTP per RFC 4226/6238. **Secrets should be random** (not passwords). If you receive Base32 (otpauth URI), decode before calling.

* **HOTP** — 6 digits, SHA-1 (default).
* **TOTP** — 30 s step, 6 digits, SHA-1 (default). `is_totp_token_valid` checks ±1 step by default.

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string key = "12345678901234567890"; // raw bytes
uint64_t counter = 0;
int hotp = get_hotp_code(key, counter);
int totp = get_totp_code(key); // now()
```

Validation example (RFC 6238 vector):

```cpp
bool ok = hmac::is_totp_token_valid(94287082, key, /*time=*/59, /*step=*/30,
                                    /*digits=*/8, hmac::TypeHash::SHA1);
```

### 🕓 Time-Based HMAC Tokens (custom)

A simple **stateless** HMAC(timestamp) scheme *(not TOTP/HOTP)*:

* Default **SHA256** (also SHA1/SHA512 supported)
* Full HMAC digest as tag (hex)
* Valid within previous/current/next interval (±`interval_sec`)
* Optional binding to a **client fingerprint** (device ID, etc.)
* **No replay protection** within the interval — use TOTP/HOTP or server-side nonce tracking for high-risk scenarios

```cpp
std::string token = hmac::generate_time_token(secret_key, /*interval=*/60);
bool valid = hmac::is_token_valid(token, secret_key, 60);

// with fingerprint
std::string t2 = hmac::generate_time_token(secret_key, fingerprint, 60);
bool v2 = hmac::is_token_valid(t2, secret_key, fingerprint, 60);
```

---

## 📦 MQL5 Compatibility

Repository provides `sha256.mqh`, `sha512.mqh`, `hmac.mqh`, `hmac_utils.mqh` (MetaTrader 5).

**Install:** copy these files into your MT5 folder, e.g. `MQL5/Include/hmac-cpp/`, then:

```mql5
#include <hmac-cpp/hmac.mqh>
string mac = hmac::get_hmac("key", "message", hmac::TypeHash::SHA256);
```

| Hash function | C++ enum                 | MQL enum                 |
| ------------- | ------------------------ | ------------------------ |
| SHA1          | `hmac::TypeHash::SHA1`   | – (not available)        |
| SHA256        | `hmac::TypeHash::SHA256` | `hmac::TypeHash::SHA256` |
| SHA512        | `hmac::TypeHash::SHA512` | `hmac::TypeHash::SHA512` |

> **Note:** C++ includes use `hmac_cpp/...` (underscore), MQL includes use `hmac-cpp/...` (dash directory name).

---

## ✅ Tests & Vectors

Enable tests and run with CTest:

```bash
cmake -B build -DHMACCPP_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Covered vectors:

* HMAC — **RFC 4231**
* PBKDF2 — **RFC 6070**
* HOTP — **RFC 4226** (Appendix D)
* TOTP — **RFC 6238** (Appendix B)

CI runs these on Linux/Windows/macOS.

---

## 📄 Example Program

`example.cpp` builds when `HMACCPP_BUILD_EXAMPLES=ON`.

```cpp
#include <iostream>
#include <hmac_cpp/hmac.hpp>
#include <hmac_cpp/hmac_utils.hpp>

int main() {
    std::string input = "grape";
    std::string key = "12345";

    std::string mac = hmac::get_hmac(key, input, hmac::TypeHash::SHA256);
    bool ok = (mac.size() == 64) &&
              hmac::constant_time_equal(
                  mac,
                  "7632ac2e8ddedaf4b3e7ab195fefd17571c37c970e02e169195a158ef59e53ca");
    if (ok) std::cout << "MAC verified\n";
}
```

Manual build after install:

```bash
g++ example.cpp -std=c++11 -I_install/include -L_install/lib -lhmac_cpp
```

MSVC:

```bat
cl /EHsc example.cpp /I _install\include /link /LIBPATH:_install\lib hmach_cpp.lib
```

---

## ⚠️ Exceptions & Contracts

* Functions may throw `std::invalid_argument` (bad params) and `std::runtime_error` (internal errors).
* `constant_time_equal` assumes lengths are public; compare sizes first.
* PBKDF2 limits: `dkLen ≤ (2^32−1)·hLen`; iterations ≥ 1; salt length ≥ 16 recommended.
* HKDF limits: `L ≤ 255·HashLen`.
* Thread-safety: functions are stateless and thread-safe given separate buffers.

---

## 📚 Resources

* Original SHA-256: [http://www.zedwood.com/article/cpp-sha256-function](http://www.zedwood.com/article/cpp-sha256-function)
* Original SHA-512: [http://www.zedwood.com/article/cpp-sha512-function](http://www.zedwood.com/article/cpp-sha512-function)
* HMAC (wiki): [https://en.wikipedia.org/wiki/HMAC](https://en.wikipedia.org/wiki/HMAC)

---

## 🔗 Related Projects

* [ADVobfuscator](https://github.com/andrivet/ADVobfuscator)
* [obfy](https://github.com/NewYaroslav/obfy)
* [aes-cpp](https://github.com/NewYaroslav/aes-cpp)
* [siphash-cpp](https://github.com/NewYaroslav/siphash-cpp)

---

## 📝 License

MIT — see [`LICENSE`](./LICENSE).
