#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <hmac_cpp/hmac.hpp>
#include <hmac_cpp/hmac_utils.hpp>

static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

static std::string serialize(const std::vector<uint8_t>& salt,
                             uint32_t iters,
                             size_t dk_len,
                             hmac::Pbkdf2Hash prf) {
    std::string salt_hex = hmac::to_hex(
        std::string(reinterpret_cast<const char*>(salt.data()), salt.size()));
    std::ostringstream oss;
    oss << salt_hex << '|' << iters << '|' << dk_len << '|' << static_cast<int>(prf);
    return oss.str();
}

static bool deserialize(const std::string& s,
                        std::vector<uint8_t>& salt,
                        uint32_t& iters,
                        size_t& dk_len,
                        hmac::Pbkdf2Hash& prf) {
    std::istringstream iss(s);
    std::string salt_hex, iters_str, dk_len_str, prf_str;
    if (!std::getline(iss, salt_hex, '|')) return false;
    if (!std::getline(iss, iters_str, '|')) return false;
    if (!std::getline(iss, dk_len_str, '|')) return false;
    if (!std::getline(iss, prf_str, '|')) return false;
    salt = from_hex(salt_hex);
    iters = static_cast<uint32_t>(std::stoul(iters_str));
    dk_len = static_cast<size_t>(std::stoul(dk_len_str));
    prf = static_cast<hmac::Pbkdf2Hash>(std::stoi(prf_str));
    return true;
}

int main() {
    std::vector<uint8_t> password{'s','e','c','r','e','t'};
    std::vector<uint8_t> salt{0,1,2,3,4,5,6,7};
    uint32_t iters = 100000;
    size_t dk_len = 32;
    hmac::Pbkdf2Hash prf = hmac::Pbkdf2Hash::Sha256;

    auto dk = hmac::pbkdf2(password, salt, iters, dk_len, prf);

    std::string header = serialize(salt, iters, dk_len, prf);
    std::cout << "serialized params: " << header << '\n';

    std::vector<uint8_t> salt2; uint32_t iters2; size_t dk_len2; hmac::Pbkdf2Hash prf2;
    if (!deserialize(header, salt2, iters2, dk_len2, prf2)) {
        std::cerr << "failed to parse header" << std::endl;
        return 1;
    }
    auto dk2 = hmac::pbkdf2(password, salt2, iters2, dk_len2, prf2);

    bool same = hmac::constant_time_equal(
        std::string(reinterpret_cast<char*>(dk.data()), dk.size()),
        std::string(reinterpret_cast<char*>(dk2.data()), dk2.size()));
    std::cout << "keys match? " << (same ? "yes" : "no") << std::endl;

    // dk would be used to decrypt your configuration here
    return same ? 0 : 1;
}
