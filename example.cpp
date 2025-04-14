#include <iostream>
#include <string>
#include "hmac.hpp"
#include "hmac_timed_token.hpp"

void print_section(const std::string& title) {
    std::cout << "=== " << title << " ===" << std::endl;
}

int main() {
    const std::string input = "grape";
    const std::string key = "12345";

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
    std::cout << "Expected: 7632ac2e8ddedaf4b3e7ab195fefd17571c37c970e02e169195a158ef59e53ca\n\n";

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
	
	// Pause before exit
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}
