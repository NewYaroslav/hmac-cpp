#include "hmac_utils.hpp"
#include <cassert>
#include <limits>
#include <iostream>

int main() {
    std::string key = "12345678901234567890";
    int digits = 6;
    uint64_t period = 30;
    uint64_t early_timestamp = 5; // less than one period

    // Token generated for counter = 0 should be valid at early timestamp
    int token_counter0 = hmac::get_hotp_code(key.data(), key.size(), 0, digits, hmac::TypeHash::SHA1);
    bool valid = hmac::is_totp_token_valid(token_counter0, key.data(), key.size(), early_timestamp, period, digits, hmac::TypeHash::SHA1);
    assert(valid);

    // Token from max counter should NOT be considered valid when timestamp is in the first period
    uint64_t max_counter = std::numeric_limits<uint64_t>::max();
    int token_max = hmac::get_hotp_code(key.data(), key.size(), max_counter, digits, hmac::TypeHash::SHA1);
    bool valid_max = hmac::is_totp_token_valid(token_max, key.data(), key.size(), early_timestamp, period, digits, hmac::TypeHash::SHA1);
    assert(!valid_max);

    std::cout << "TOTP early timestamp test passed" << std::endl;
    return 0;
}
