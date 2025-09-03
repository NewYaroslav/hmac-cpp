#include <gtest/gtest.h>
#include <string>
#include <stdexcept>
#include <vector>
#include <limits>
#include <cerrno>

#include "hmac.hpp"
#include "hmac_utils.hpp"

static std::time_t mock_time_value = 0;
static int mock_errno_value = 0;
extern "C" std::time_t time(std::time_t* t) {
    if (t) *t = mock_time_value;
    errno = mock_errno_value;
    return mock_time_value;
}

TEST(HashTest, SHA1) {
    EXPECT_EQ(hmac_hash::sha1("grape"),
              "bc8a2f8cdedb005b5c787692853709b060db75ff");
}

TEST(HashTest, SHA256) {
    EXPECT_EQ(hmac_hash::sha256("grape"),
              "0f78fcc486f5315418fbf095e71c0675ee07d318e5ac4d150050cd8e57966496");
}

TEST(HashTest, SHA512) {
    EXPECT_EQ(hmac_hash::sha512("grape"),
              "9375d1abdb644a01955bccad12e2f5c2bd8a3e226187e548d99c559a99461453b980123746753d07c169c22a5d9cc75cb158f0e8d8c0e713559775b5e1391fc4");
}

TEST(HashTest, SHA512LargeInput) {
    hmac_hash::SHA512 ctx;
    ctx.init();
    std::vector<uint8_t> chunk(1024 * 1024, 'a');
    for (size_t i = 0; i < 4096; ++i) {
        ctx.update(chunk.data(), chunk.size());
    }
    uint8_t tail = 'b';
    ctx.update(&tail, 1);

    uint8_t digest[hmac_hash::SHA512::DIGEST_SIZE];
    ctx.finish(digest);
    std::string result(reinterpret_cast<char*>(digest), hmac_hash::SHA512::DIGEST_SIZE);
    EXPECT_EQ(hmac::to_hex(result),
              "596d71e02b4eca81f668215d3e9b9e5a143a9c3d8d1981608e0811b20e290961ec2a7e7ecd0e275366cf10aa5f7ab1e052b868c5fa57b6d2bd6e75477b2ecea7");
}

TEST(HashTest, InvalidTypeThrowsString) {
    auto invalid = static_cast<hmac::TypeHash>(999);
    EXPECT_THROW(hmac::get_hash("grape", invalid), std::invalid_argument);
}

TEST(HashTest, InvalidTypeThrowsBuffer) {
    auto invalid = static_cast<hmac::TypeHash>(999);
    const char data[] = "grape";
    EXPECT_THROW(hmac::get_hash(data, sizeof(data) - 1, invalid), std::invalid_argument);
}

TEST(UtilsTest, ToHex) {
    EXPECT_EQ(hmac::to_hex("012345"), "303132333435");
}

TEST(UtilsTest, ConstantTimeEqualsMatch) {
    EXPECT_TRUE(hmac::constant_time_equals("alpha", "alpha"));
}

TEST(UtilsTest, ConstantTimeEqualsMismatch) {
    EXPECT_FALSE(hmac::constant_time_equals("alpha", "beta"));
    EXPECT_FALSE(hmac::constant_time_equals("alpha", "alphabet"));
}

TEST(UtilsTest, ConstantTimeEqualsLengthMultiples256) {
    std::string base(256, 'a');
    std::string plus256 = base + std::string(256, '\0');
    std::string plus512 = base + std::string(512, '\0');
    EXPECT_FALSE(hmac::constant_time_equals(base, plus256));
    EXPECT_FALSE(hmac::constant_time_equals(base, plus512));
}

TEST(HMACTest, SHA256) {
    const std::string key = "12345";
    const std::string input = "grape";
    EXPECT_EQ(hmac::get_hmac(key, input, hmac::TypeHash::SHA256, true),
              "7632ac2e8ddedaf4b3e7ab195fefd17571c37c970e02e169195a158ef59e53ca");
}

TEST(HMACTest, SHA512) {
    const std::string key = "12345";
    const std::string input = "grape";
    EXPECT_EQ(hmac::get_hmac(key, input, hmac::TypeHash::SHA512, true),
              "c54ddf9647a949d0df925a1c1f8ba1c9d721a671c396fde1062a71f9f7ffae5dc10f6be15be63bb0363d051365e23f890368c54828497b9aef2eb2fc65b633e6");
}

TEST(HMACTest, SHA512Uppercase) {
    const std::string key = "12345";
    const std::string input = "grape";
    EXPECT_EQ(hmac::get_hmac(key, input, hmac::TypeHash::SHA512, true, true),
              "C54DDF9647A949D0DF925A1C1F8BA1C9D721A671C396FDE1062A71F9F7FFAE5DC10F6BE15BE63BB0363D051365E23F890368C54828497B9AEF2EB2FC65B633E6");
}

TEST(HMACTest, NullPointersThrow) {
    const char* msg = "abc";
    EXPECT_THROW(hmac::get_hmac(nullptr, 1, msg, 3, hmac::TypeHash::SHA256), std::invalid_argument);
    const char* key = "key";
    EXPECT_THROW(hmac::get_hmac(key, 3, nullptr, 1, hmac::TypeHash::SHA256), std::invalid_argument);
}

TEST(HMACTest, InvalidTypeThrows) {
    const char* key = "key";
    const char* msg = "abc";
    auto invalid = static_cast<hmac::TypeHash>(999);
    EXPECT_THROW(hmac::get_hmac(key, 3, msg, 3, invalid), std::invalid_argument);
}

TEST(HMACTest, InvalidTypeThrowsString) {
    const std::string key = "key";
    const std::string msg = "abc";
    auto invalid = static_cast<hmac::TypeHash>(999);
    EXPECT_THROW(hmac::get_hmac(key, msg, invalid), std::invalid_argument);
}

TEST(TOTPTest, AtTime) {
    const std::string totp_key = "12345678901234567890";
    uint64_t test_time = 1234567890;
    int code = hmac::get_totp_code_at(totp_key, test_time, 30, 8, hmac::TypeHash::SHA1);
    EXPECT_EQ(code, 89005924);
}

TEST(TokenTest, InvalidInterval) {
    const std::string key = "12345";
    std::string token = hmac::generate_time_token(key, 60);
    EXPECT_THROW(hmac::generate_time_token(key, 0), std::invalid_argument);
    EXPECT_THROW(hmac::is_token_valid(token, key, 0), std::invalid_argument);
}

TEST(TokenBoundaryTest, MaxTime) {
    const std::string key = "12345";
    const int interval = 30;
    mock_time_value = std::numeric_limits<std::time_t>::max();
    std::string token = hmac::generate_time_token(key, interval);
    EXPECT_TRUE(hmac::is_token_valid(token, key, interval));
    mock_time_value = std::numeric_limits<std::time_t>::max() - interval;
    std::string token_prev = hmac::generate_time_token(key, interval);
    mock_time_value = std::numeric_limits<std::time_t>::max();
    EXPECT_TRUE(hmac::is_token_valid(token_prev, key, interval));
}

TEST(TokenBoundaryTest, MinTime) {
    const std::string key = "12345";
    const int interval = 30;
    mock_time_value = std::numeric_limits<std::time_t>::min();
    std::string token = hmac::generate_time_token(key, interval);
    EXPECT_TRUE(hmac::is_token_valid(token, key, interval));
    mock_time_value = std::numeric_limits<std::time_t>::min() + interval;
    std::string token_next = hmac::generate_time_token(key, interval);
    mock_time_value = std::numeric_limits<std::time_t>::min();
    EXPECT_TRUE(hmac::is_token_valid(token_next, key, interval));
}

TEST(TokenBoundaryFingerprintTest, MaxTime) {
    const std::string key = "12345";
    const std::string fingerprint = "fp";
    const int interval = 30;
    mock_time_value = std::numeric_limits<std::time_t>::max();
    std::string token = hmac::generate_time_token(key, fingerprint, interval);
    EXPECT_TRUE(hmac::is_token_valid(token, key, fingerprint, interval));
    mock_time_value = std::numeric_limits<std::time_t>::max() - interval;
    std::string token_prev = hmac::generate_time_token(key, fingerprint, interval);
    mock_time_value = std::numeric_limits<std::time_t>::max();
    EXPECT_TRUE(hmac::is_token_valid(token_prev, key, fingerprint, interval));
}

TEST(TokenBoundaryFingerprintTest, MinTime) {
    const std::string key = "12345";
    const std::string fingerprint = "fp";
    const int interval = 30;
    mock_time_value = std::numeric_limits<std::time_t>::min();
    std::string token = hmac::generate_time_token(key, fingerprint, interval);
    EXPECT_TRUE(hmac::is_token_valid(token, key, fingerprint, interval));
    mock_time_value = std::numeric_limits<std::time_t>::min() + interval;
    std::string token_next = hmac::generate_time_token(key, fingerprint, interval);
    mock_time_value = std::numeric_limits<std::time_t>::min();
    EXPECT_TRUE(hmac::is_token_valid(token_next, key, fingerprint, interval));
}

TEST(TimeErrorTest, MinusOneNoErrno) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = 0;
    std::string token;
    EXPECT_NO_THROW(token = hmac::generate_time_token(key));
    EXPECT_EQ(token, hmac::get_hmac(key, "0", hmac::TypeHash::SHA256));
    mock_time_value = 0;
    mock_errno_value = 0;
}

TEST(TimeErrorTest, MinusOneWithErrno) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = EINVAL;
    EXPECT_THROW(hmac::generate_time_token(key), std::runtime_error);
    mock_errno_value = 0;
    mock_time_value = 0;
}

TEST(TotpTimeErrorTest, MinusOneNoErrno) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = 0;
    EXPECT_NO_THROW(hmac::get_totp_code(key));
    mock_time_value = 0;
    mock_errno_value = 0;
}

TEST(TotpTimeErrorTest, MinusOneWithErrno) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = EINVAL;
    EXPECT_THROW(hmac::get_totp_code(key), std::runtime_error);
    mock_errno_value = 0;
    mock_time_value = 0;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

