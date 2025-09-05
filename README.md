# hmac-cpp [🇷🇺 README-RU](./README-RU.md)

[![Linux](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml)
[![Windows](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml)

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

Use CMake to build:

```bash
cmake -B build -DBUILD_EXAMPLE=ON
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

Predefined `.bat` scripts for MinGW builds are also available: `build_*.bat`.

After installation, the package can be found and linked in other projects using `find_package`:

```cmake
find_package(hmac_cpp CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE hmac_cpp::hmac_cpp)
```

## 🧪 Running Tests

Enable tests during configuration and run them with CTest:

```bash
cmake -B build -DBUILD_TESTS=ON
cmake --build build
cd build
ctest --output-on-failure
```

Alternatively, use the helper script:

```bash
scripts/run_tests.sh
```

## 📦 MQL5 Compatibility

The repository includes `sha256.mqh`, `sha512.mqh`, `hmac.mqh`, and `hmac_utils.mqh` files, fully compatible with `MetaTrader 5`.

You can use the same interface inside your MQL5 scripts and experts:

```mql5
#include <hmac-cpp/hmac.mqh>

string hash = hmac::get_hmac("key", "message", hmac::TypeHash::HASH_SHA256);
```

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

### PBKDF2 Key Derivation

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string password = "password";
std::vector<uint8_t> salt(16, 0x01); // at least 16 bytes
std::vector<uint8_t> dk = hmac::pbkdf2(password, salt, 1000, 32);
```

Parameters:

- `password`, `salt` — Raw byte arrays. `salt` must be **>=16 bytes** and unique.
- `iterations` — Number of iterations (>=1). Tune according to the
  [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- `dk_len` — Desired key length in bytes, up to `(2^32-1) * hLen` (RFC 8018).
- `prf` — Optional hash (`Sha1`, `Sha256` default, `Sha512`).

⚠️ Low iteration counts or short salts reduce security.

For deployments with a server-side *pepper*, use `pbkdf2_with_pepper(password, salt, pepper, iters, dkLen)`.
The pepper is a secret key stored separately from the hashed password.

### HKDF (RFC 5869)

```cpp
std::vector<uint8_t> ikm = {/* secret material */};
std::vector<uint8_t> salt(16, 0x00);
auto prk = hmac::hkdf_extract_sha256(ikm, salt);
auto okm = hmac::hkdf_expand_sha256(prk, {}, 32); // derive 32 bytes
```

### 🕓 HOTP and TOTP Tokens

The library supports generating one-time passwords based on RFC 4226 and RFC 6238.

#### HOTP (HMAC-based One-Time Password)

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string key = "12345678901234567890"; // raw key
uint64_t counter = 0;
int otp = get_hotp_code(key, counter); // defaults: 6 digits, SHA1
std::cout << "HOTP: " << otp << std::endl;
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

### 🕓 Time-Based HMAC Tokens (Custom HMAC Time Tokens)

The library also includes a **lightweight implementation of time-based HMAC tokens**, which are not directly based on RFC 4226/6238 (HOTP/TOTP). These tokens:

- Are based on `HMAC(timestamp)`
- Are returned as `hex` strings
- Require no server-side state (stateless)
- Support binding to a *client fingerprint* (e.g. device ID)
- Support `SHA1`, `SHA256`, and `SHA512`

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

The example is in `example.cpp` and is built automatically when `BUILD_EXAMPLE=ON`.

```cpp
#include <iostream>
#include <hmac_cpp/hmac.hpp>

int main() {
    std::string input = "grape";
    std::string key = "12345";

    std::string hmac_sha256 = hmac::get_hmac(key, input, hmac::TypeHash::SHA256);
    std::cout << "HMAC-SHA256: " << hmac_sha256 << std::endl;

    std::string hmac_sha512 = hmac::get_hmac(key, input, hmac::TypeHash::SHA512);
    std::cout << "HMAC-SHA512: " << hmac_sha512 << std::endl;

    return 0;
}
```

## 📚 Resources

* Original [SHA256 implementation](http://www.zedwood.com/article/cpp-sha256-function)
* Original [SHA512 implementation](http://www.zedwood.com/article/cpp-sha512-function)
* Algorithm description on [Wikipedia](https://ru.wikipedia.org/wiki/HMAC)

## 🔗 Related Projects

- [ADVobfuscator](https://github.com/andrivet/ADVobfuscator)
- [obfy](https://github.com/NewYaroslav/obfy)
- [aescpp](https://github.com/NewYaroslav/aescpp)
- [siphash-hpp](https://github.com/NewYaroslav/siphash-hpp)

## 📝 License

This project is licensed under the **MIT License**.
You are free to use, copy, modify, and distribute this software, provided that the original license notice is included.

See the [`LICENSE`](./LICENSE) file for full details.