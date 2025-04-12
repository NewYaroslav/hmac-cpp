# hmac-cpp [🇷🇺 README-RU](./README-RU.md)

A lightweight `C++11` library for computing `HMAC` (hash-based message authentication code), supporting `SHA256` and `SHA512`.

## 🚀 Features

- Compatible with **C++11**
- Supports `HMAC` using `SHA256` and `SHA512`
- Outputs in binary or hex format
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
│   ├── sha256.hpp
│   └── sha512.hpp
└── lib/
    └── libhmac.a
```

Predefined `.bat` scripts for MinGW builds are also available: `build_*.bat`.

## Usage

HMAC function:

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