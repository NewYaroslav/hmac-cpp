#include <iostream>
#include <string>
#include <stdexcept>
#include <hmac_cpp/hmac.hpp>
#include <hmac_cpp/hmac_utils.hpp>

void print_section(const std::string& title) {
    std::cout << "=== " << title << " ===" << std::endl;
}

int main() {
    const std::string input = "grape";
    const std::string key = "12345";
    
    // SHA1
    print_section("SHA1");
    std::string sha1_output = hmac_hash::sha1(input);
    std::cout << "sha1('" << input << "') = " << sha1_output << std::endl;
    std::cout << "Expected: bc8a2f8cdedb005b5c787692853709b060db75ff\n\n";

    // SHA256
    print_section("SHA256");
    std::string sha256_output = hmac_hash::sha256(input);
    std::cout << "sha256('" << input << "') = " << sha256_output << std::endl;
    std::cout << "Expected: 0f78fcc486f5315418fbf095e71c0675ee07d318e5ac4d150050cd8e57966496\n\n";

    // SHA512
    print_section("SHA512");
    std::string sha512_output = hmac_hash::sha512(input);
    std::cout << "sha512('" << input << "') = " << sha512_output << std::endl;
    std::cout << "Expected: 9375d1abdb644a01955bccad12e2f5c2bd8a3e226187e548d99c559a99461453b980123746753d07c169c22a5d9cc75cb158f0e8d8c0e713559775b5e1391fc4\n\n";

    // to_hex
    print_section("to_hex");
    std::string hex_output = hmac::to_hex("012345");
    std::cout << "to_hex(\"012345\") = " << hex_output << std::endl << std::endl;

    // HMAC-SHA256
    print_section("HMAC-SHA256");
    std::string hmac_sha256 = hmac::get_hmac(key, input, hmac::TypeHash::SHA256, true);
    std::cout << "HMAC('" << key << "', '" << input << "', SHA256) = " << hmac_sha256 << std::endl;
    std::string expected_hmac_sha256 =
            "7632ac2e8ddedaf4b3e7ab195fefd17571c37c970e02e169195a158ef59e53ca";
    bool mac_valid = hmac::constant_time_equal(hmac_sha256, expected_hmac_sha256);
    std::cout << "MAC valid? = " << (mac_valid ? "YES" : "NO") << "\n\n";

    // HMAC-SHA512
    print_section("HMAC-SHA512");
    std::string hmac_sha512 = hmac::get_hmac(key, input, hmac::TypeHash::SHA512, true);
    std::cout << "HMAC('" << key << "', '" << input << "', SHA512) = " << hmac_sha512 << std::endl;
    std::cout << "Expected: c54ddf9647a949d0df925a1c1f8ba1c9d721a671c396fde1062a71f9f7ffae5dc10f6be15be63bb0363d051365e23f890368c54828497b9aef2eb2fc65b633e6\n\n";

    // HMAC-SHA512 uppercase hex
    print_section("HMAC-SHA512 (uppercase)");
    std::string hmac_sha512_upper = hmac::get_hmac(key, input, hmac::TypeHash::SHA512, true, true);
    std::cout << "HMAC('" << key << "', '" << input << "', SHA512, hex=true, upper=true) = " << hmac_sha512_upper << std::endl;

    // HMAC TIME TOKEN
    print_section("HMAC-TIMED TOKEN");
    std::string time_token = hmac::generate_time_token(key, 60);
    std::cout << "Time token (now) = " << time_token << std::endl;
    bool valid = hmac::is_token_valid(time_token, key, 60);
    std::cout << "Token valid? = " << (valid ? "YES" : "NO") << std::endl;

    // HMAC TIME TOKEN + fingerprint
    print_section("HMAC-TIMED TOKEN (with fingerprint)");
    std::string fingerprint = "my-client-unique-id";
    std::string timed_token = hmac::generate_time_token(key, fingerprint, 60);
    std::cout << "Fingerprint = " << fingerprint << std::endl;
    std::cout << "Token = " << timed_token << std::endl;
    bool valid_fp = hmac::is_token_valid(timed_token, key, fingerprint, 60);
    std::cout << "Token valid (with fingerprint)? = " << (valid_fp ? "YES" : "NO") << std::endl;

    // HMAC TIME TOKEN with invalid interval
    print_section("HMAC-TIMED TOKEN (invalid interval)");
    try {
        hmac::generate_time_token(key, 0);
    } catch (const std::invalid_argument& e) {
        std::cout << "generate_time_token error: " << e.what() << std::endl;
    }
    try {
        hmac::is_token_valid(time_token, key, 0);
    } catch (const std::invalid_argument& e) {
        std::cout << "is_token_valid error: " << e.what() << std::endl;
    }

    // TOTP
    std::string totp_key = "12345678901234567890"; // raw binary string (not base32!)
    uint64_t test_time = 1234567890;
    int code = hmac::get_totp_code_at(totp_key, test_time, 30, 8, hmac::TypeHash::SHA1);
    std::cout << "TOTP: " << code << std::endl;
    std::cout << "Expected: 89005924\n\n";
    
    // Pause before exit
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
