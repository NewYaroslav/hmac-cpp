# hmac-cpp

[![Linux](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Linux.yml)
[![Windows](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/hmac-cpp/actions/workflows/CI-Win.yml)

Лёгкая `C++11` библиотека для вычисления `HMAC` (hash-based message authentication code), поддерживающая поддерживающая `SHA256`, `SHA512`, `SHA1`, а также одноразовые пароли `HOTP` и `TOTP`.

## 🚀 Возможности

- Совместимость с **C++11**
- Поддержка `HMAC` на основе `SHA256`, `SHA512`, `SHA1`
- Прямая работа с бинарным или hex-форматом
- Поддержка **временных токенов**:
    - **HOTP (RFC 4226)** — счётчики
    - **TOTP (RFC 6238)** — временные токены
    - **HMAC Time Tokens** — облегчённые временные токены с HMAC-подписью и интервалом
- Поддержка **MQL5** — адаптированные версии SHA/HMAC для MetaTrader 
- Статическая сборка через CMake
- Пример использования в комплекте

## 🔧 Установка и сборка

Для сборки используйте CMake:

```bash
cmake -B build -DBUILD_EXAMPLE=ON
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

Также в репозитории есть готовые `.bat`-файлы для сборки под MinGW: `build_*.bat`.

## 📦 MQL5-совместимость

В репозитиории содержатся файлы `sha256.mqh`, `sha512.mqh`, `hmac.mqh`, `hmac_utils.mqh`, полностью совместимые с `MetaTrader 5`.

Вы можете использовать аналогичные вызовы в скриптах и советниках:

```mql5
#include <hmac-cpp/hmac.mqh>

string hash = hmac::get_hmac("key", "message", hmac::TypeHash::HASH_SHA256);
```

## Использование

### HMAC (ввод в виде строки)

```cpp
std::string get_hmac(
    std::string key,
    const std::string& msg,
    const TypeHash type,
    bool is_hex = true,
    bool is_upper = false
);
```

Параметры:

- `key` — Секретный ключ
- `msg` — Сообщение
- `type` — Тип хеш-функции: `hmac::TypeHash::SHA256` или `SHA512`
- `is_hex` — Возвращать hex-строку (`true`) или бинарные данные (`false`) [по умолчанию: true]
- `is_upper` — Использовать верхний регистр (только для `hex`) [по умолчанию: false]

Возвращает:  
Если `is_hex == true`, возвращает HMAC в виде hex-строки (`std::string`).  
Если `is_hex == false`, возвращает HMAC в виде бинарной строки (`std::string`, не предназначена для вывода).

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

### 🕓 HOTP и TOTP токены

Библиотека поддерживает генерацию одноразовых паролей по RFC 4226 и RFC 6238.

#### HOTP (HMAC-based One-Time Password)

```cpp
#include <hmac_cpp/hmac_utils.hpp>

std::string key = "12345678901234567890"; // raw key
uint64_t counter = 0;
int otp = get_hotp_code(key, counter); // по умолчанию: 6 цифр, SHA1
std::cout << "HOTP: " << otp << std::endl;
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

### 🕓 Временные токены на основе HMAC (Custom HMAC Time Tokens)

Библиотека также включает **облегчённую реализацию временных HMAC-токенов**, не связанную напрямую с RFC 4226/6238 (HOTP/TOTP). Эти токены:

- Основаны на `HMAC(timestamp)`
- Возвращаются в виде `hex`-строки
- Не требуют хранения состояния (stateless)
- Поддерживают привязку к отпечатку клиента (например, ID устройства)
- Поддерживают `SHA1`, `SHA256` и `SHA512`

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

Пример находится в `example.cpp`, автоматически собирается при `BUILD_EXAMPLE=ON`.

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