#include <gtest/gtest.h>
#include <limits>
#include "hmac_cpp/hmac_utils.hpp"

TEST(TotpBoundaryTest, EarlyTimestampValidatesCounterZero) {
    std::string key = "12345678901234567890";
    int digits = 6;
    uint64_t period = 30;
    uint64_t early_timestamp = 5; // less than one period
    int token = hmac::get_hotp_code(key.data(), key.size(), 0, digits, hmac::TypeHash::SHA1);
    EXPECT_TRUE(hmac::is_totp_token_valid(token, key.data(), key.size(), early_timestamp, period, digits, hmac::TypeHash::SHA1));
}

TEST(TotpBoundaryTest, MaxCounterInvalidAtEarlyTimestamp) {
    std::string key = "12345678901234567890";
    int digits = 6;
    uint64_t period = 30;
    uint64_t early_timestamp = 5;
    uint64_t max_counter = std::numeric_limits<uint64_t>::max();
    int token = hmac::get_hotp_code(key.data(), key.size(), max_counter, digits, hmac::TypeHash::SHA1);
    EXPECT_FALSE(hmac::is_totp_token_valid(token, key.data(), key.size(), early_timestamp, period, digits, hmac::TypeHash::SHA1));
}

TEST(TotpBoundaryTest, MaxTimestampDoesNotValidateCounterZero) {
    std::string key = "12345678901234567890";
    int digits = 6;
    uint64_t max_timestamp = std::numeric_limits<uint64_t>::max();
    int token = hmac::get_hotp_code(key.data(), key.size(), 0, digits, hmac::TypeHash::SHA1);
    EXPECT_FALSE(hmac::is_totp_token_valid(token, key.data(), key.size(), max_timestamp, 1, digits, hmac::TypeHash::SHA1));
}

TEST(TotpBoundaryTest, MaxTimestampValidatesMaxCounter) {
    std::string key = "12345678901234567890";
    int digits = 6;
    uint64_t max_timestamp = std::numeric_limits<uint64_t>::max();
    uint64_t max_counter = std::numeric_limits<uint64_t>::max();
    int token = hmac::get_hotp_code(key.data(), key.size(), max_counter, digits, hmac::TypeHash::SHA1);
    EXPECT_TRUE(hmac::is_totp_token_valid(token, key.data(), key.size(), max_timestamp, 1, digits, hmac::TypeHash::SHA1));
}
