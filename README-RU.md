# hmac-cpp

Лёгкая C++11-библиотека для вычисления `HMAC` (hash-based message authentication code), поддерживающая `SHA256` и `SHA512`.

## 🚀 Возможности

- Совместимость с **C++11**
- Поддержка `HMAC` на основе `SHA256` и `SHA512`
- Прямая работа с бинарным или hex-форматом
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
│   ├── sha256.hpp
│   └── sha512.hpp
└── lib/
    └── libhmac.a
```

Также в репозитории есть готовые `.bat`-файлы для сборки под MinGW: `build_*.bat`.

## Использование

HMAC-функция:

```cpp
std::string get_hmac(
    std::string key,
    const std::string& msg,
    const TypeHash type,
    bool is_hex = true,
    bool is_upper = false
);
```

**Параметры:**

- `key` — Секретный ключ
- `msg` — Сообщение
- `type` — Тип хеш-функции `hmac::TypeHash`. Указать `SHA256` или `SHA512`
- `is_hex` — Вернуть hex-строку (`true`) или бинарную (`false`) [по умолчанию: true]
- `is_upper` — Использовать верхний регистр (только для `hex`) [по умолчанию: false]

## 📄 Пример

Пример находится в `example.cpp`, автоматически собирается при `BUILD_EXAMPLE=ON`.

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

## 📚 Полезные ссылки

* Исходный код [SHA256](http://www.zedwood.com/article/cpp-sha256-function)
* Исходный код [SHA512](http://www.zedwood.com/article/cpp-sha512-function)
* Описание алгоритма [HMAC](https://ru.wikipedia.org/wiki/HMAC)


## 📝 Лицензия

Проект распространяется под лицензией **MIT**.  
Это означает, что вы можете свободно использовать, копировать, модифицировать и распространять код, при условии сохранения оригинального уведомления о лицензии.

См. файл [`LICENSE`](./LICENSE) для подробностей.