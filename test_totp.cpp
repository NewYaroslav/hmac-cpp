#include <gtest/gtest.h>
#include <limits>
#include "hmac_cpp/hmac_utils.hpp"

TEST(HOTPTest, RFC4226Vectors) {
    const std::string key = "12345678901234567890";
    const int digits = 6;
    struct Case { uint64_t counter; int code; } cases[] = {
        {0, 755224}, {1, 287082}, {2, 359152}, {3, 969429}, {4, 338314},
        {5, 254676}, {6, 287922}, {7, 162583}, {8, 399871}, {9, 520489},
    };
    for (const auto& c : cases) {
        EXPECT_EQ(hmac::get_hotp_code(key.data(), key.size(), c.counter, digits, hmac::TypeHash::SHA1), c.code);
    }
}

TEST(TOTPTest, RFC6238SHA1) {
    const std::string key = "12345678901234567890";
    const int digits = 8;
    struct Case { uint64_t time; int code; } cases[] = {
        {59, 94287082}, {1111111109, 7081804}, {1111111111, 14050471},
        {1234567890, 89005924}, {2000000000, 69279037}, {20000000000ULL, 65353130},
    };
    for (const auto& c : cases) {
        EXPECT_EQ(hmac::get_totp_code_at(key.data(), key.size(), c.time, 30, digits, hmac::TypeHash::SHA1), c.code);
    }
}

TEST(TOTPTest, RFC6238SHA256) {
    const std::string key = "12345678901234567890123456789012";
    const int digits = 8;
    struct Case { uint64_t time; int code; } cases[] = {
        {59, 46119246}, {1111111109, 68084774}, {1111111111, 67062674},
        {1234567890, 91819424}, {2000000000, 90698825}, {20000000000ULL, 77737706},
    };
    for (const auto& c : cases) {
        EXPECT_EQ(hmac::get_totp_code_at(key.data(), key.size(), c.time, 30, digits, hmac::TypeHash::SHA256), c.code);
    }
}

TEST(TOTPTest, RFC6238SHA512) {
    const std::string key = "1234567890123456789012345678901234567890123456789012345678901234";
    const int digits = 8;
    struct Case { uint64_t time; int code; } cases[] = {
        {59, 90693936}, {1111111109, 25091201}, {1111111111, 99943326},
        {1234567890, 93441116}, {2000000000, 38618901}, {20000000000ULL, 47863826},
    };
    for (const auto& c : cases) {
        EXPECT_EQ(hmac::get_totp_code_at(key.data(), key.size(), c.time, 30, digits, hmac::TypeHash::SHA512), c.code);
    }
}

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
