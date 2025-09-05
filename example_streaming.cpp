#include <array>
#include <fstream>
#include <iostream>
#include <string>

// stream large files in chunks and verify
#include <hmac_cpp/hmac.hpp>
#include <hmac_cpp/hmac_utils.hpp>

int main() {
    const std::string key = "supersecret";
    const std::string path = "large.bin"; // path to large file

    hmac::HmacContext ctx(hmac::TypeHash::SHA256);
    ctx.init(key.data(), key.size());

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open " << path << "\n";
        return 1;
    }

    std::array<char, 4096> buf{};
    while (in.good()) {
        in.read(buf.data(), buf.size());
        std::streamsize got = in.gcount();
        if (got > 0) {
            ctx.update(buf.data(), static_cast<size_t>(got));
        }
    }

    std::array<uint8_t, 32> mac{};
    ctx.final(mac.data(), mac.size());

    std::string mac_hex = hmac::to_hex(
        std::string(reinterpret_cast<char*>(mac.data()), mac.size()));

    const std::string expected_hex = "<expected hmac>"; // known good value
    bool ok = hmac::constant_time_equal(mac_hex, expected_hex);
    std::cout << "HMAC valid? " << (ok ? "yes" : "no") << std::endl;
    return ok ? 0 : 1;
}
