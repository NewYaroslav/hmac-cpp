# hmac-cpp
C++ Библиотека для расчета HMAC

## Особенности библиотеки

Это очень простая библиотека для *C++11*, при помощи которой можно легко посчитать [HMAC](https://ru.wikipedia.org/wiki/HMAC) (hash-based message authentication code, код аутентификации (проверки подлинности) сообщений, использующий хеш-функции). 
На данный момент библиотека поддерживает только две хеш-функции: **SHA256** и **SHA512**.
Для расчета HMAC надо вызвать функцию *get_hmac*, которая имеет несколько параметров:

```cpp
std::string get_hmac(
	std::string key, 
	const std::string &msg, 
	const TypeHash type, 
	const bool is_hex = true, 
	const bool is_upper = false);
```

* key - Строка, содержащая секретный ключ.
* msg - Строка, содержащая сообщение.
* type - Тип хеш-функции. Указать **hmac::TypeHash::SHA256** или **hmac::TypeHash::SHA512**.
* is_hex - Флаг, который отвечает за формат ответа. Чтобы получить строку, содержащую **HMAC** в шестнадцетиричном формате, данный параметр должен быть указан как true. Иначе строка будет содержать числовое значение HMAC по 8 бит в каждом элеименте строки. **По умолчанию данный параметр true.**
* is_upper - Флаг, который отвечает за регистр символов ответа (нижний или верхний). Данный флаг влияет на ответ функции только если установлен флаг is_hex. **По умолчанию данный параметр true.**

## Как пользоваться

Простой пример кода для расчета **HMAC SHA256 и SHA512**:

```cpp
#include <iostream>
#include <hmac.hpp>

int main() {
	std::string input("grape");
	std::string key("12345");
	
	/* проверяем работу HMAC SHA256 */
    std::string output1 = hmac::get_hmac(key, input, hmac::TypeHash::SHA256);
    std::cout << "get_hmac('"<< key << "','" << input << "',SHA256): " << output1 << std::endl;
    std::cout << "The answer should be: "
        "7632ac2e8ddedaf4b3e7ab195fefd17571c37c970e02e169195a158ef59e53ca"
        << std::endl << std::endl;

    /* проверяем работу HMAC SHA512 */
    std::string output2 = hmac::get_hmac(key, input, hmac::TypeHash::SHA512);
    std::cout << "get_hmac('"<< key << "','" << input << "',SHA512): " << output2 << std::endl;
    std::cout << "The answer should be: "
        "c54ddf9647a949d0df925a1c1f8ba1c9d721a671c396fde1062a71f9f7ffae5dc10f6be15be63bb0363d051365e23f890368c54828497b9aef2eb2fc65b633e6"
        << std::endl << std::endl;
	return 0;
}
```

Чтобы программу удалось скомпилировать, добавьте в проект все файлы исходников: *sha256.cpp, sha512.cpp*.
Пример проекта для Code::Blocks использует нестандартные настройки компилятора, поэтому не забудьте поменять компилятор в проекте перед сборкой.

## Ссылки на ресурсы

* Исходный код [SHA256](http://www.zedwood.com/article/cpp-sha256-function)
* Исходный код [SHA512](http://www.zedwood.com/article/cpp-sha512-function)
* Описание алгоритма [HMAC](https://ru.wikipedia.org/wiki/HMAC)


