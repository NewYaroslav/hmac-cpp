# hmac-cpp [🇷🇺 README-RU](./README-RU.md)

[![Linux](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml)
[![Windows](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml)
[![macOS](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-macOS.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-macOS.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight `C++11` library for computing `HMAC` (hash-based message authentication codes), supporting `SHA1`, `SHA256`, `SHA512`, as well as one-time passwords compliant with `HOTP` (RFC 4226) and `TOTP` (RFC 6238).

## 🚀 Features

- Compatible with **C++11**
- Supports `HMAC` using `SHA256`, `SHA512`, `SHA1`
- Outputs in binary or hex format
- Provides **PBKDF2 key derivation** (RFC 8018)
- Implements **HKDF (RFC 5869)** for key extraction/expansion
- Support for **time-based tokens**:
    - **HOTP (RFC 4226)** — counter-based one-time passwords
    - **TOTP (RFC 6238)** — time-based one-time passwords
    - **HMAC Time Tokens** — lightweight HMAC-based tokens with rotation interval
- Includes **MQL5 support** — adapted SHA/HMAC versions for MetaTrader
- Static build via CMake
- Example program included

## 🔧 Build and Installation

Examples, tests, and benchmarks are disabled by default. Enable them with
`HMACCPP_BUILD_EXAMPLES`, `HMACCPP_BUILD_TESTS`, and `HMACCPP_BUILD_BENCH`.

Use CMake to build:

```bash
cmake -B build -DHMACCPP_BUILD_EXAMPLES=ON
cmake --build build
```

To install the library and headers:

```bash
cmake --install build --prefix _install
```

This will create the following structure:

```
_install/
├── include/hmac_cpp/
│   ├── hmac.hpp
│   ├── hmac_utils.hpp
│   ├── sha1.hpp
│   ├── sha256.hpp
│   └── sha512.hpp
    └── lib/
        └── libhmac_cpp.a
```

Include headers in your code as `<hmac_cpp/...>`

Predefined `.bat` scripts for MinGW builds are also available: `build_*.bat`.

After installation, the package can be found and linked in other projects using `find_package`:

```cmake
find_package(hmac_cpp CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE hmac_cpp::hmac_cpp)
```

## 🧪 Running Tests

Enable tests during configuration and run them with CTest:

```bash
cmake -B build -DHMACCPP_BUILD_TESTS=ON
cmake --build build
cd build
ctest --output-on-failure
```

Alternatively, use the helper script:

```bash
scripts/run_tests.sh
```

## Test Vectors

The test suite covers official vectors from [RFC&nbsp;4231](https://www.rfc-editor.org/rfc/rfc4231) and [RFC&nbsp;6070](https://www.rfc-editor.org/rfc/rfc6070) and runs in CI.

## 📦 MQL5 Compatibility

The repository includes `sha256.mqh`, `sha512.mqh`, `hmac.mqh`, and `hmac_utils.mqh` files, fully compatible with `MetaTrader 5`.

You can use the same interface inside your MQL5 scripts and experts:

```mql5
#include <hmac-cpp/hmac.mqh>

string hash = hmac::get_hmac("key", "message", hmac::TypeHash::SHA256);
```

| Hash function | C++ enum              | MQL enum              |
|---------------|----------------------|-----------------------|
| SHA1          | `hmac::TypeHash::SHA1`| – (not available)     |
| SHA256        | `hmac::TypeHash::SHA256` | `hmac::TypeHash::SHA256` |
| SHA512        | `hmac::TypeHash::SHA512` | `hmac::TypeHash::SHA512` |

## Usage

### HMAC (string input)

```cpp
std::string get_hmac(
    std::string key,
    const std::string& msg,
    const TypeHash type,
    bool is_hex = true,
    bool is_upper = false
);
```

Parameters:

- `key` — Secret key
- `msg` — Message
- `type` — Hash type: `hmac::TypeHash::SHA256` or `SHA512`
- `is_hex` — Return hex string (`true`) or raw binary (`false`) [default: true]
- `is_upper` — Use uppercase hex (only applies if `is_hex == true`) [default: false]

Returns:
If `is_hex == true`, returns a hexadecimal string (`std::string`) of the HMAC.
If `is_hex == false`, returns a raw binary HMAC as a `std::string` (not human-readable).

#### Secure handling of string keys

When a secret key is obtained as a `std::string` (e.g. an API key from an exchange),
move it into a `secure_buffer` to erase the original string immediately:

```cpp
#include <cstdlib>
#include <hmac_cpp/secure_buffer.hpp>

std::string api_key = std::getenv("API_KEY");
secure_buffer key(std::move(api_key)); // api_key is zeroized

std::vector<uint8_t> sig =
    hmac::get_hmac(key, payload, hmac::TypeHash::SHA256);
secure_zero(key); // optional: wipe after use
```

### HMAC (binary data: raw buffer)

```cpp
std::vector<uint8_t> get_hmac(
    const void* key_ptr,
    size_t key_len,
    const void* msg_ptr,
    size_t msg_len,
    TypeHash type
);
```

Parameters:

- `key_ptr` — Pointer to secret key buffer
- `key_len` — Length of key in bytes
- `msg_ptr` — Pointer to message buffer
- `msg_len` — Length of message in bytes
- `type` — Hash type

Returns: Binary digest as `std::vector<uint8_t>`

### HMAC (vectors)

```cpp
template<typename T>
std::vector<uint8_t> get_hmac(
    const std::vector<T>& key,
    const std::vector<T>& msg,
    TypeHash type
);
```

Template requirement: `T` must be `char` or `uint8_t`

Parameters:

- `key` — Vector containing the key
- `msg` — Vector containing the message
- `type` — Hash type

Returns: Binary digest as `std::vector<uint8_t>`

### PBKDF2

PBKDF2 derives a cryptographic key from a user password. It is typically
used to unlock encrypted data or verify password hashes.

```cpp
#include <hmac_cpp/hmac_utils.hpp>
auto salt = hmac::random_bytes(16);
auto key  = hmac::pbkdf2_hmac_sha256(password, salt, iters, 32);
```

Recommendations:

- **Salt:** 16–32 random bytes.
- **Iterations:** pick a value so derivation takes ~100–250 ms on the target
  machine.
- **Derived key length:** 32 bytes.
- **Algorithm:** HMAC-SHA-256.

Parameters and ciphertext may be serialized as:
`magic|salt|iters|iv|ct|tag`.

See `example_pbkdf2.cpp` for a complete example.

#### Recommended Parameters

| Target  | Iterations | Derived key length | PRF |
|---------|-----------:|------------------:|-----|
| Desktop | 600000     | 32 bytes          | HMAC-SHA256 |
| Laptop  | 300000     | 32 bytes          | HMAC-SHA256 |
| Mobile  | 150000     | 32 bytes          | HMAC-SHA256 |

#### Security Notes

- PBKDF2 is CPU-bound and vulnerable to massive GPU/ASIC brute force.
  Choose high iteration counts or stronger KDFs.
- Every password requires a unique, random salt of sufficient length.
- Salts, iteration counts, and algorithms are not secrets—store them
  alongside the hash or ciphertext.

### HKDF (RFC 5869)

```cpp
std::vector<uint8_t> ikm = {/* secret material */};
std::vector<uint8_t> salt(16, 0x00);
auto prk = hmac::hkdf_extract_sha256(ikm, salt);
auto okm = hmac::hkdf_expand_sha256(prk, {}, 32); // derive 32 bytes
```

### 🕓 HOTP and TOTP Tokens

The library supports generating one-time passwords based on RFC 4226 and RFC 6238.
Secrets are supplied as raw bytes. If you receive a Base32 string (common in OTP
URIs), decode it before calling the functions.

- **HOTP** — 6 digits, SHA-1.
- **TOTP** — 30 s period, 6 digits, SHA-1. `is_totp_token_valid` accepts tokens
  from the previous and next interval (±1).

#### HOTP (HMAC-based One-Time Password)

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string key = "12345678901234567890"; // raw key
uint64_t counter = 0;
int otp = get_hotp_code(key, counter); // defaults: 6 digits, SHA1
std::cout << "HOTP: " << otp << std::endl;
bool ok = (otp == 755224); // RFC 4226 test vector
```

#### TOTP (Time-based One-Time Password)

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string key = "12345678901234567890"; // raw key
int otp = get_totp_code(key); // defaults: 30s period, 6 digits, SHA1
std::cout << "TOTP: " << otp << std::endl;
```

You can also generate a code for a specific timestamp:

```cpp
uint64_t time_at = 1700000000;
int otp = get_totp_code_at(key, time_at);
```

To verify a received code:

```cpp
bool valid = hmac::is_totp_token_valid(94287082, key, 59, 30, 8, hmac::TypeHash::SHA1); // RFC 6238 test vector
```

Known test vectors: [RFC 4226 Appendix D](https://www.rfc-editor.org/rfc/rfc4226#appendix-D) and [RFC 6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).

### 🕓 Time-Based HMAC Tokens (Custom HMAC Time Tokens)

The library also includes a **lightweight implementation of time-based HMAC tokens**. This is *not* TOTP or HOTP; it's a simple `HMAC(timestamp)` approach. These tokens:

- Are based on `HMAC(timestamp)`
- Default to `SHA256` but also support `SHA1` and `SHA512`
- Use the full HMAC digest as the tag (32 bytes → 64 hex chars with `SHA256`)
- Are returned as lowercase `hex` strings
- Are valid for the previous, current, and next interval (±`interval_sec`)
- Require no server-side state (stateless)
- Support binding to a *client fingerprint* (e.g. device ID)
- Provide basic replay protection and are intended for low-risk scenarios

#### Example:

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string token = hmac::generate_time_token(secret_key, 60);
bool is_valid = hmac::is_token_valid(token, secret_key, 60);
```

You can also bind the token to a *client fingerprint*:

```cpp
std::string token = hmac::generate_time_token(secret_key, fingerprint, 60);
bool is_valid = hmac::is_token_valid(token, secret_key, fingerprint, 60);
```

If `interval_sec` is not positive, the functions throw `std::invalid_argument`:

```cpp
try {
    hmac::generate_time_token(secret_key, 0);
} catch (const std::invalid_argument& e) {
    std::cout << e.what();
}
```

This is useful for stateless authentication, API protection, and one-time tokens.

## 📄 Example

The example is in `example.cpp` and builds when `HMACCPP_BUILD_EXAMPLES=ON`.

```cpp
#include <iostream>
#include <hmac_cpp/hmac.hpp>
#include <hmac_cpp/hmac_utils.hpp>

int main() {
    std::string input = "grape";
    std::string key = "12345";

    std::string mac = hmac::get_hmac(key, input, hmac::TypeHash::SHA256);
    if (hmac::constant_time_equal(mac,
            "7632ac2e8ddedaf4b3e7ab195fefd17571c37c970e02e169195a158ef59e53ca")) {
        std::cout << "MAC verified\n";
    }

    return 0;
}
```

**Note:** avoid checking input lengths before calling `constant_time_equal`.
Early length comparisons can leak information through timing side channels.

## 📚 Resources

* Original [SHA256 implementation](http://www.zedwood.com/article/cpp-sha256-function)
* Original [SHA512 implementation](http://www.zedwood.com/article/cpp-sha512-function)
* Algorithm description on [Wikipedia](https://ru.wikipedia.org/wiki/HMAC)

## 🔗 Related Projects

- [ADVobfuscator](https://github.com/andrivet/ADVobfuscator)
- [obfy](https://github.com/NewYaroslav/obfy)
- [aes-cpp](https://github.com/NewYaroslav/aes-cpp)
- [siphash-cpp](https://github.com/NewYaroslav/siphash-cpp)

## 📝 License

This project is licensed under the **MIT License**.
You are free to use, copy, modify, and distribute this software, provided that the original license notice is included.

See the [`LICENSE`](./LICENSE) file for full details.
