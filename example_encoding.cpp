#include <iostream>
#include <string>
#include <vector>
#include <hmac_cpp/encoding.hpp>
#include <hmac_cpp/secure_buffer.hpp>

int main() {
    std::vector<uint8_t> data = {'f','o','o','b','a','r'};
    std::string b64 = hmac_cpp::base64_encode(data);
    std::cout << "Base64: " << b64 << std::endl;

    std::vector<uint8_t> decoded;
    hmac_cpp::base64_decode(b64, decoded);
    std::cout << "Decoded: " << std::string(decoded.begin(), decoded.end()) << std::endl;

    std::string b32 = hmac_cpp::base32_encode(data);
    std::cout << "Base32: " << b32 << std::endl;

    hmac_cpp::secure_buffer<uint8_t> sec;
    hmac_cpp::base32_decode(b32, sec);
    std::cout << "Decoded secure size: " << sec.size() << std::endl;
    return 0;
}
