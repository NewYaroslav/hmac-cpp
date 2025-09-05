# hmac-cpp

[![Linux](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml)
[![Windows](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml)
[![macOS](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-macOS.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-macOS.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Лёгкая `C++11` библиотека для вычисления `HMAC` (hash-based message authentication code), поддерживающая поддерживающая `SHA256`, `SHA512`, `SHA1`, а также одноразовые пароли `HOTP` и `TOTP`.

## 🚀 Возможности

- Совместимость с **C++11**
- Поддержка `HMAC` на основе `SHA256`, `SHA512`, `SHA1`
- Прямая работа с бинарным или hex-форматом
- Поддержка **PBKDF2** (RFC 8018)
- Поддержка **HKDF** (RFC 5869) для извлечения и расширения ключей
- Поддержка **временных токенов**:
    - **HOTP (RFC 4226)** — счётчики
    - **TOTP (RFC 6238)** — временные токены
    - **HMAC Time Tokens** — облегчённые временные токены с HMAC-подписью и интервалом
- Поддержка **MQL5** — адаптированные версии SHA/HMAC для MetaTrader 
- Статическая сборка через CMake
- Пример использования в комплекте

## 🔧 Установка и сборка

По умолчанию примеры, тесты и бенчмарки не собираются. Включите их с помощью
`HMACCPP_BUILD_EXAMPLES`, `HMACCPP_BUILD_TESTS` и `HMACCPP_BUILD_BENCH`.

Для сборки используйте CMake:

```bash
cmake -B build -DHMACCPP_BUILD_EXAMPLES=ON
cmake --build build
```

Чтобы установить библиотеку и заголовки:

```bash
cmake --install build --prefix _install
```

Это создаст структуру:

```
_install/
├── include/hmac_cpp/
│   ├── hmac.hpp
│   ├── hmac_utils.hpp
│   ├── sha1.hpp
│   ├── sha256.hpp
│   └── sha512.hpp
└── lib/
    └── libhmac.a
```

Подключайте заголовки как `<hmac_cpp/...>`

Также в репозитории есть готовые `.bat`-файлы для сборки под MinGW: `build_*.bat`.

## 📦 MQL5-совместимость

В репозитиории содержатся файлы `sha256.mqh`, `sha512.mqh`, `hmac.mqh`, `hmac_utils.mqh`, полностью совместимые с `MetaTrader 5`.

Вы можете использовать аналогичные вызовы в скриптах и советниках:

```mql5
#include <hmac-cpp/hmac.mqh>

string hash = hmac::get_hmac("key", "message", hmac::TypeHash::SHA256);
```

| Хеш-функция | Значение в C++           | Значение в MQL           |
|-------------|--------------------------|--------------------------|
| SHA1        | `hmac::TypeHash::SHA1`   | – (не доступно)          |
| SHA256      | `hmac::TypeHash::SHA256` | `hmac::TypeHash::SHA256` |
| SHA512      | `hmac::TypeHash::SHA512` | `hmac::TypeHash::SHA512` |

## Использование

### HMAC (ввод в виде строки)

```cpp
std::string get_hmac(
    const std::string& key,
    const std::string& msg,
    TypeHash type,
    bool is_hex = true,
    bool is_upper = false);
```

Параметры:

- `key` — Секретный ключ
- `msg` — Сообщение
- `type` — Тип хеш-функции: `hmac::TypeHash::SHA256` или `SHA512`
- `is_hex` — Возвращать hex-строку (`true`) или бинарные данные (`false`) [по умолчанию: true]
- `is_upper` — Использовать верхний регистр (только для `hex`) [по умолчанию: false]

Возвращает:
Если `is_hex == true`, возвращает HMAC в виде hex-строки (`std::string`).
Если `is_hex == false`, возвращает бинарную строку; для бинарного вывода предпочтительнее перегрузка со `std::vector<uint8_t>`.

#### Безопасная работа со строковыми ключами

Если секретный ключ получен в виде `std::string` (например, API‑ключ биржи),
переместите его в `secure_buffer`, чтобы исходная строка сразу очистилась:

```cpp
#include <cstdlib>
#include <hmac_cpp/secure_buffer.hpp>

std::string api_key = std::getenv("API_KEY");
secure_buffer key(std::move(api_key)); // api_key очищена

auto sig = hmac::get_hmac(key, payload, hmac::TypeHash::SHA256);
secure_zero(key); // при необходимости: очистить после использования
```

Чтобы сравнить два токена напрямую, используйте
`hmac::constant_time_equal` для защиты от атак по времени:

```cpp
bool same = hmac::constant_time_equal(expected_token, user_token); // длины публичны
```

### HMAC (сырые бинарные данные)

```cpp
std::vector<uint8_t> get_hmac(
    const void* key_ptr,
    size_t key_len,
    const void* msg_ptr,
    size_t msg_len,
    TypeHash type
);
```

Параметры:

- `key_ptr` — Указатель на буфер с ключом
- `key_len` — Размер ключа в байтах
- `msg_ptr` — Указатель на буфер с сообщением
- `msg_len` — Размер сообщения в байтах
- `type` — Тип хеш-функции

Возвращает: Бинарный HMAC в виде `std::vector<uint8_t>`

### HMAC (векторы)

```cpp
template<typename T>
std::vector<uint8_t> get_hmac(
    const std::vector<T>& key,
    const std::vector<T>& msg,
    TypeHash type
);
```

Требования шаблона: `T` должен быть `char` или `uint8_t`

Параметры:

- `key` — Вектор, содержащий ключ
- `msg` — Вектор, содержащий сообщение
- `type` — Тип хеш-функции

Возвращает: Бинарный HMAC в виде `std::vector<uint8_t>`

### PBKDF2

PBKDF2 преобразует пароль пользователя в криптографический ключ.
Используется для шифрования и хранения хешей паролей.

```cpp
#include <hmac_cpp/hmac_utils.hpp>
auto salt = hmac::random_bytes(16);
auto key  = hmac::pbkdf2_hmac_sha256(password, salt, iters, 32);
```

Рекомендации:

- **Соль:** случайные 16–32 байта.
- **Итерации:** подбирайте число так, чтобы вычисление занимало ~100–250 мс на целевой машине.
- **Длина ключа:** 32 байта.
- **Алгоритм:** HMAC-SHA-256.

Параметры и шифротекст можно сериализовать, например, так:
`magic|salt|iters|iv|ct|tag`.

См. `example_pbkdf2.cpp` для полноценного примера.

#### Рекомендуемые параметры

| Цель   | Итерации | Длина ключа | PRF         |
|--------|---------:|------------:|-------------|
| Desktop| 600000   | 32 байта    | HMAC-SHA256 |
| Laptop | 300000   | 32 байта    | HMAC-SHA256 |
| Mobile | 150000   | 32 байта    | HMAC-SHA256 |

#### Примечания по безопасности

- PBKDF2 зависит от CPU и уязвим для атак с использованием GPU/ASIC, поэтому выбирайте высокое число итераций или более сильные KDF.
- Каждому паролю нужна уникальная случайная соль достаточной длины.
- Соль, итерации и алгоритм не являются секретом — храните их вместе с хешем или шифротекстом.

### 🕓 HOTP и TOTP токены

Библиотека поддерживает генерацию одноразовых паролей по RFC 4226 и RFC 6238.
Секрет передаётся в виде сырых байт. Если он задан в Base32 (часто в OTP URI),
сначала декодируйте его.

- **HOTP** — 6 цифр, SHA-1.
- **TOTP** — период 30 с, 6 цифр, SHA-1. `is_totp_token_valid` допускает окно ±1 интервал.

#### HOTP (HMAC-based One-Time Password)

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string key = "12345678901234567890"; // raw key
uint64_t counter = 0;
int otp = get_hotp_code(key, counter); // по умолчанию: 6 цифр, SHA1
std::cout << "HOTP: " << otp << std::endl;
bool ok = (otp == 755224); // тестовый вектор RFC 4226
```

#### TOTP (Time-based One-Time Password)

```
#include <hmac_cpp/hmac_utils.hpp>

std::string key = "12345678901234567890"; // raw key
int otp = get_totp_code(key); // по умолчанию: 30 сек, 6 цифр, SHA1
std::cout << "TOTP: " << otp << std::endl;
```

Можно задать конкретную метку времени:

```cpp
uint64_t time_at = 1700000000;
int otp = get_totp_code_at(key, time_at);
```

Для проверки кода:

```cpp
bool valid = hmac::is_totp_token_valid(94287082, key, 59, 30, 8, hmac::TypeHash::SHA1); // тестовый вектор RFC 6238
```

Известные тестовые векторы: [RFC 4226, приложение D](https://www.rfc-editor.org/rfc/rfc4226#appendix-D) и [RFC 6238, приложение B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).

### 🕓 Временные токены на основе HMAC (Custom HMAC Time Tokens)

Библиотека также включает **облегчённую реализацию временных HMAC-токенов**. Это **не** TOTP/HOTP; используется простой механизм `HMAC(timestamp)`. Эти токены:

- Основаны на `HMAC(timestamp)` — не TOTP/HOTP
- По умолчанию применяется `SHA256` (поддерживаются также `SHA1` и `SHA512`)
- Тег — полный HMAC: 32 байта (64 hex-символа) при `SHA256`
- Кодирование: `hex` в нижнем регистре
- Токен принимается для предыдущего, текущего и следующего интервала (±`interval_sec`)
- Не требуют хранения состояния и могут привязываться к *отпечатку клиента* (например, ID устройства)
- Обеспечивают базовую защиту от повторного воспроизведения и подходят только для задач с низким риском

Пример использования:

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string token = hmac::generate_time_token(secret_key, 60);
bool is_valid = hmac::is_token_valid(token, secret_key, 60);
```

Также можно привязать токен к *отпечатку клиента* (fingerprint):

```cpp
std::string token = hmac::generate_time_token(secret_key, fingerprint, 60);
bool is_valid = hmac::is_token_valid(token, secret_key, fingerprint, 60);
```

Если `interval_sec` неположителен, функции выбросят `std::invalid_argument`:

```cpp
try {
    hmac::generate_time_token(secret_key, 0);
} catch (const std::invalid_argument& e) {
    std::cout << e.what();
}
```

Подходит для авторизации, защиты API и одноразовых токенов.

## 📄 Пример

Пример находится в `example.cpp` и собирается при `HMACCPP_BUILD_EXAMPLES=ON`.

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
        std::cout << "MAC проверен\n";
    }

    return 0;
}
```

**Примечание:** `constant_time_equal` считает длину входных данных публичной и
время работы зависит от максимальной длины. Не проверяйте длины отдельно —
ранние проверки могут выдать информацию через побочные каналы времени
выполнения.

Скомпилировать пример вручную после установки:

```bash
g++ example.cpp -std=c++11 -Iinclude -Llib -lhmac_cpp
```

Для MSVC:

```bat
cl /EHsc example.cpp /I include /link libhmac_cpp.lib
```

## 📚 Полезные ссылки

* Исходный код [SHA256](http://www.zedwood.com/article/cpp-sha256-function)
* Исходный код [SHA512](http://www.zedwood.com/article/cpp-sha512-function)
* Описание алгоритма [HMAC](https://ru.wikipedia.org/wiki/HMAC)

## 🔗 Другие проекты

- [ADVobfuscator](https://github.com/andrivet/ADVobfuscator)
- [obfy](https://github.com/NewYaroslav/obfy)
- [aescpp](https://github.com/NewYaroslav/aescpp)
- [siphash-hpp](https://github.com/NewYaroslav/siphash-hpp)

## 📝 Лицензия

Проект распространяется под лицензией **MIT**.  
Это означает, что вы можете свободно использовать, копировать, модифицировать и распространять код, при условии сохранения оригинального уведомления о лицензии.

См. файл [`LICENSE`](./LICENSE) для подробностей.
