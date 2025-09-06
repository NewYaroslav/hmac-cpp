# hmac-cpp [English README](./README.md)

[![Linux](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml)
[![Windows](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml)
[![macOS](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-macOS.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-macOS.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Лёгкая библиотека **C++11** для вычисления **HMAC** (SHA-1/SHA-256/SHA-512), вывода ключей (**PBKDF2**, **HKDF**) и одноразовых паролей (**HOTP**, **TOTP**). Включает упрощённые **временные HMAC-токены** для статeless-сценариев и совместима с **MQL5**.

---

## 🚀 Возможности

* Совместимость с **C++11**
* HMAC на основе **SHA1**, **SHA256**, **SHA512**
* Вывод в **бинарном** или **hex**-формате
* **PBKDF2** (RFC 8018) — вывод ключа из пароля
* **HKDF** (RFC 5869) — извлечение/расширение ключа
* **OTP**:
  * **HOTP** (RFC 4226) — счётчик
  * **TOTP** (RFC 6238) — время
* **Временные HMAC-токены** — облегчённые токены на основе HMAC(timestamp) *(не TOTP/HOTP)*
* **Поддержка MQL5** — адаптированные SHA/HMAC для MetaTrader 5
* Экспортируемая цель пакета CMake: **`hmac_cpp::hmac_cpp`**

---

## ⚙️ Платформы и компиляторы

CI охватывает Linux/Windows/macOS. Тестировалась с GCC, Clang и MSVC; требуется C++11.

---

## 🔧 Сборка и установка

Примеры, тесты и бенчмарки по умолчанию отключены. Включаются опциями:

* `HMACCPP_BUILD_EXAMPLES`
* `HMACCPP_BUILD_TESTS`
* `HMACCPP_BUILD_BENCH`

### Сборка

```bash
cmake -B build -DHMACCPP_BUILD_EXAMPLES=ON
cmake --build build
```

### Установка

```bash
cmake --install build --prefix _install
```

Структура установки:

```
_install/
├─ include/hmac_cpp/
│  ├─ hmac.hpp
│  ├─ hmac_utils.hpp
│  ├─ sha1.hpp
│  ├─ sha256.hpp
│  ├─ sha512.hpp
│  └─ secure_buffer.hpp    # если включён в сборку
└─ lib/
   └─ libhmac_cpp.a
```

### Использование с CMake

```cmake
find_package(hmac_cpp CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE hmac_cpp::hmac_cpp)
```

### Ручная компиляция после установки

```bash
# подберите пути под свой префикс
g++ example.cpp -std=c++11 -I_install/include -L_install/lib -lhmac_cpp
```

Предусмотрены скрипты сборки для MinGW: `build_*.bat`.

---

## 📘 Использование

> **Замечание по SHA-1**: HMAC-SHA1 поддерживается для совместимости/OTP. Для новых проектов предпочтительны HMAC-SHA256/512.

### HMAC (строковый ввод)

```cpp
std::string get_hmac(
    const std::string& key,
    const std::string& msg,
    TypeHash type,
    bool is_hex = true,
    bool is_upper = false);
```

* `type`: `hmac::TypeHash::SHA256` / `SHA512` / `SHA1`
* По умолчанию возвращается hex. Для **бинарного** вывода используйте перегрузку со `std::vector<uint8_t>`.

**Сравнение в постоянное время** — длины считаются публичными:

```cpp
bool equal = (a.size() == b.size()) && hmac::constant_time_equal(a, b);
```

**(Опционально) Безопасная работа со строковыми ключами** — при использовании `secure_buffer`:

```cpp
#include <hmac_cpp/secure_buffer.hpp>
secure_buffer key(std::move(secret_string)); // обнуляет перемещённую строку
auto mac = hmac::get_hmac(key, payload, hmac::TypeHash::SHA256);
```

### PBKDF2 (RFC 8018)

Вывод ключа из пароля.

```cpp
#include <hmac_cpp/hmac_utils.hpp>
auto salt = hmac::random_bytes(16);
auto key  = hmac::pbkdf2_hmac_sha256(password, salt, iters, 32); // 32 = AES-256
```

**Рекомендации**

* **Соль**: 16–32 случайных байт (уникальна для каждого пароля). Храните рядом с шифротекстом.
* **Итерации**: подберите ~100–250 мс на целевой платформе (настольный ≈ 600k, ноутбук ≈ 300k, мобильный ≈ 150k).
* **Длина ключа**: 32 байта; **PRF**: HMAC-SHA256.

**Пример сериализации** (бинарный):

```
magic(4) | ver(1) | alg(1=PBKDF2-HS256) |
iter(4, BE) | salt_len(1) | salt | iv_len(1) | iv | ct_len(4, BE) | ct | tag(16)
```

Смотрите `example_pbkdf2.cpp` для полного примера.

### HKDF (RFC 5869)

```cpp
std::vector<uint8_t> ikm = {/* секретные данные */};
std::vector<uint8_t> salt(16, 0x00);
auto prk = hmac::hkdf_extract_sha256(ikm, salt);
auto okm = hmac::hkdf_expand_sha256(prk, /*info=*/{}, /*L=*/32); // L ≤ 255*HashLen
```

### Base64 / Base32

Утилиты для кодирования/декодирования Base64 (обычный и URL-алфавит) и Base32.

```cpp
#include <hmac_cpp/encoding.hpp>

std::vector<uint8_t> key = {0xff, 0xee};
std::string b64 = hmac_cpp::base64_encode(key, hmac_cpp::Base64Alphabet::Url, false);
hmac_cpp::secure_buffer<uint8_t> raw;
hmac_cpp::base64_decode(b64, raw, hmac_cpp::Base64Alphabet::Url, false);
```

### 🕓 HOTP / TOTP

OTP по RFC 4226/6238. **Секреты должны быть случайными** (не паролями). Если получаете Base32 (otpauth URI), декодируйте перед вызовом.

* **HOTP** — 6 цифр, SHA-1 (по умолчанию).
* **TOTP** — шаг 30 с, 6 цифр, SHA-1 (по умолчанию). `is_totp_token_valid` проверяет ±1 шаг.

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string key = "12345678901234567890"; // сырые байты
uint64_t counter = 0;
int hotp = get_hotp_code(key, counter);
int totp = get_totp_code(key); // now()
```

Пример проверки (вектор RFC 6238):

```cpp
bool ok = hmac::is_totp_token_valid(94287082, key, /*time=*/59, /*step=*/30,
                                    /*digits=*/8, hmac::TypeHash::SHA1);
```

### 🕓 Временные токены на основе HMAC (кастомные)

Простая **stateless** схема `HMAC(timestamp)` *(не TOTP/HOTP)*:

* По умолчанию **SHA256** (поддерживаются также SHA1/SHA512)
* Тег — полный HMAC в hex
* Токен действителен в предыдущем/текущем/следующем интервале (±`interval_sec`)
* Возможна привязка к **отпечатку клиента** (ID устройства и т.п.)
* **Нет защиты от повторов** внутри интервала — для критичных задач используйте TOTP/HOTP или серверный учёт nonce

```cpp
std::string token = hmac::generate_time_token(secret_key, /*interval=*/60);
bool valid = hmac::is_token_valid(token, secret_key, 60);

// с отпечатком
std::string t2 = hmac::generate_time_token(secret_key, fingerprint, 60);
bool v2 = hmac::is_token_valid(t2, secret_key, fingerprint, 60);
```

---

## 📦 Совместимость с MQL5

Репозиторий предоставляет `sha256.mqh`, `sha512.mqh`, `hmac.mqh`, `hmac_utils.mqh` (MetaTrader 5).

**Установка:** скопируйте файлы в каталог MT5, например `MQL5/Include/hmac-cpp/`, затем:

```mql5
#include <hmac-cpp/hmac.mqh>
string mac = hmac::get_hmac("key", "message", hmac::TypeHash::SHA256);
```

| Хеш-функция | C++ enum                 | MQL enum                 |
|-------------|-------------------------|--------------------------|
| SHA1        | `hmac::TypeHash::SHA1`   | – (недоступно)           |
| SHA256      | `hmac::TypeHash::SHA256` | `hmac::TypeHash::SHA256` |
| SHA512      | `hmac::TypeHash::SHA512` | `hmac::TypeHash::SHA512` |

> **Примечание:** в C++ используется `hmac_cpp/...` (подчёркивание), в MQL — `hmac-cpp/...` (дефис).

---

## ✅ Тесты и векторы

Включите тесты и запустите их через CTest:

```bash
cmake -B build -DHMACCPP_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Покрытые векторы:

* HMAC — **RFC 4231**
* PBKDF2 — **RFC 6070**
* HOTP — **RFC 4226** (Appendix D)
* TOTP — **RFC 6238** (Appendix B)

CI запускает их на Linux/Windows/macOS.

---

## 📄 Пример программы

`example.cpp` собирается при `HMACCPP_BUILD_EXAMPLES=ON`.

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

Ручная компиляция после установки:

```bash
g++ example.cpp -std=c++11 -I_install/include -L_install/lib -lhmac_cpp
```

MSVC:

```bat
cl /EHsc example.cpp /I _install\\include /link /LIBPATH:_install\\lib hmach_cpp.lib
```

---

## ⚠️ Исключения и контракты

* Функции могут бросать `std::invalid_argument` (неверные параметры) и `std::runtime_error` (внутренние ошибки).
* `constant_time_equal` предполагает публичность длин; сравнивайте размеры заранее.
* Ограничения PBKDF2: `dkLen ≤ (2^32−1)·hLen`; итераций ≥ 1; рекомендуемая длина соли ≥ 16 байт.
* Ограничения HKDF: `L ≤ 255·HashLen`.
* Потокобезопасность: функции статичны и потокобезопасны при раздельных буферах.

---

## 📚 Источники

* Оригинальный SHA-256: [http://www.zedwood.com/article/cpp-sha256-function](http://www.zedwood.com/article/cpp-sha256-function)
* Оригинальный SHA-512: [http://www.zedwood.com/article/cpp-sha512-function](http://www.zedwood.com/article/cpp-sha512-function)
* HMAC (wiki): [https://en.wikipedia.org/wiki/HMAC](https://en.wikipedia.org/wiki/HMAC)

---

## 🔗 Связанные проекты

* [ADVobfuscator](https://github.com/andrivet/ADVobfuscator)
* [obfy](https://github.com/NewYaroslav/obfy)
* [aes-cpp](https://github.com/NewYaroslav/aes-cpp)
* [siphash-cpp](https://github.com/NewYaroslav/siphash-cpp)

---

## 📝 Лицензия

MIT — см. [`LICENSE`](./LICENSE).

