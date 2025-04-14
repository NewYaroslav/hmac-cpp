# hmac-cpp [🇷🇺 README-RU](./README-RU.md)

A lightweight `C++11` library for computing `HMAC` (hash-based message authentication code), supporting `SHA256` and `SHA512`.

## 🚀 Features

- Compatible with **C++11**
- Supports `HMAC` using `SHA256` and `SHA512`
- Outputs in binary or hex format
- Supports **time-based HMAC tokens**
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
│   ├── hmac_timed_token.hpp
│   ├── sha256.hpp
│   └── sha512.hpp
└── lib/
    └── libhmac.a
```

Predefined `.bat` scripts for MinGW builds are also available: `build_*.bat`.

## 📦 MQL5 Compatibility

The repository includes `sha256.mqh`, `sha512.mqh`, `hmac.mqh`, and `hmac_timed_token.mqh` files, fully compatible with `MetaTrader 5`.

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

### 🕓 Time-Based Tokens

The library supports generation and validation of tokens that rotate every N seconds:

```cpp
#include <hmac_timed_token.hpp>

std::string token = hmac::generate_time_token(secret_key, 60);
bool is_valid = hmac::is_token_valid(token, secret_key, 60);
```

You can also bind the token to a client *fingerprint*:

```cpp
std::string token = hmac::generate_time_token(secret_key, fingerprint, 60);
bool is_valid = hmac::is_token_valid(token, secret_key, fingerprint, 60);
```

This is useful for lightweight stateless authentication.

## 📄 Example

The example is in `example.cpp` and is built automatically when `BUILD_EXAMPLE=ON`.

```cpp
#include <iostream>
#include <hmac.hpp>

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


## 📝 License

This project is licensed under the **MIT License**.
You are free to use, copy, modify, and distribute this software, provided that the original license notice is included.

See the [`LICENSE`](./LICENSE) file for full details.