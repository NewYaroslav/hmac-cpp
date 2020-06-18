#include <iostream>
#include <hmac.hpp>

int main() {
    std::cout << "Hello world!" << std::endl;
    std::string input("grape");

    /* проверяем работу SHA256 */
    std::string output1 = hmac_hash::sha256(input);
    std::cout << "sha256('"<< input << "'): " << output1 << std::endl;
    std::cout << "The answer should be: "
        "0f78fcc486f5315418fbf095e71c0675ee07d318e5ac4d150050cd8e57966496"
        << std::endl << std::endl;

    /* проверяем работу SHA512 */
    std::string output2 = hmac_hash::sha512(input);
    std::cout << "sha512('"<< input << "'): " << output2 << std::endl;
    std::cout << "The answer should be: "
        "9375d1abdb644a01955bccad12e2f5c2bd8a3e226187e548d99c559a99461453b980123746753d07c169c22a5d9cc75cb158f0e8d8c0e713559775b5e1391fc4"
        << std::endl << std::endl;

    /* проверяем работу to_hex */
    std::string output3 = hmac::to_hex("012345");
    std::cout << "to_hex('012345'): " << output3 << std::endl << std::endl;

    std::string key("12345");

    /* проверяем работу hmac SHA256 */
    std::string output4 = hmac::get_hmac(key, input, hmac::TypeHash::SHA256, true);
    std::cout << "get_hmac('"<< key << "','" << input << "',SHA256): " << output4 << std::endl;
    std::cout << "The answer should be: "
        "7632ac2e8ddedaf4b3e7ab195fefd17571c37c970e02e169195a158ef59e53ca"
        << std::endl << std::endl;

    /* проверяем работу HMAC SHA512 */
    std::string output5 = hmac::get_hmac(key, input, hmac::TypeHash::SHA512, true);
    std::cout << "get_hmac('"<< key << "','" << input << "',SHA512): " << output5 << std::endl;
    std::cout << "The answer should be: "
        "c54ddf9647a949d0df925a1c1f8ba1c9d721a671c396fde1062a71f9f7ffae5dc10f6be15be63bb0363d051365e23f890368c54828497b9aef2eb2fc65b633e6"
        << std::endl << std::endl;

    /* проверяем работу HMAC SHA512 для верхнего регистра */
    std::string output6 = hmac::get_hmac(key, input, hmac::TypeHash::SHA512, true, true);
    std::cout << "get_hmac('"<< key << "','" << input << "',SHA512, true, true): " << output6 << std::endl;
    return 0;
}
