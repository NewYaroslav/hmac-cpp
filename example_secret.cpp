#include <iostream>
#include <hmac_cpp/secret_string.hpp>

int main() {
    hmac_cpp::secret_string token("super-secret-token");

    token.with_plaintext([](const uint8_t* p, size_t n){
        std::cout.write(reinterpret_cast<const char*>(p), n);
    });
    std::cout << '\n';
    return 0;
}
