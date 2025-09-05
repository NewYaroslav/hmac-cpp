#include <gtest/gtest.h>
#include <string>
#include <stdexcept>
#include <vector>
#include <limits>
#include <cerrno>
#include <random>
#include <openssl/evp.h>

#include "hmac_cpp/hmac.hpp"
#include "hmac_cpp/hmac_utils.hpp"

static std::time_t mock_time_value = 0;
static int mock_errno_value = 0;
extern "C" std::time_t time(std::time_t* t) {
    if (t) *t = mock_time_value;
    errno = mock_errno_value;
    return mock_time_value;
}

static std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byte = hex.substr(i, 2);
        out.push_back(static_cast<uint8_t>(std::stoi(byte, nullptr, 16)));
    }
    return out;
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

TEST(UtilsTest, ConstantTimeEqualsVector) {
    std::vector<uint8_t> a = {1, 2, 3};
    std::vector<uint8_t> b = {1, 2, 3};
    EXPECT_TRUE(hmac::constant_time_equals(a, b));
    b[2] = 4;
    EXPECT_FALSE(hmac::constant_time_equals(a, b));
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

TEST(HMACTest, MsgLenOverflowThrows) {
    const char key[] = "key";
    const char msg[] = "a";
    size_t huge_len = std::numeric_limits<size_t>::max() -
                       hmac_hash::SHA256::SHA224_256_BLOCK_SIZE + 1;
    EXPECT_THROW(hmac::get_hmac(key, sizeof(key) - 1, msg, huge_len,
                                hmac::TypeHash::SHA256), std::overflow_error);
}

TEST(HMACTest, InvalidTypeThrowsString) {
    const std::string key = "key";
    const std::string msg = "abc";
    auto invalid = static_cast<hmac::TypeHash>(999);
    EXPECT_THROW(hmac::get_hmac(key, msg, invalid), std::invalid_argument);
}

TEST(HOTPTest, ShortDigestThrows) {
    std::vector<uint8_t> short_digest = {0x00, 0x01, 0x02};
    EXPECT_THROW(hmac::detail::hotp_from_digest(short_digest, 6), std::runtime_error);
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

TEST(PBKDF2Validation, ShortSaltThrows) {
    EXPECT_THROW(hmac::pbkdf2("password", "salt", 2, 20, hmac::Pbkdf2Hash::Sha1), std::invalid_argument);
}

TEST(PBKDF2Test, SHA256WithValidSalt) {
    auto salt = from_hex("000102030405060708090a0b0c0d0e0f");
    std::string salt_str(salt.begin(), salt.end());
    auto dk = hmac::pbkdf2(std::string("password"), salt_str, 2, 32, hmac::Pbkdf2Hash::Sha256);
    std::vector<uint8_t> ref(32);
    ASSERT_TRUE(PKCS5_PBKDF2_HMAC("password", 8, salt.data(), salt.size(), 2, EVP_sha256(), ref.size(), ref.data()));
    EXPECT_TRUE(hmac::constant_time_equals(dk, ref));
}

// SHA512 vector from BoringSSL pbkdf_test.cc
TEST(PBKDF2Test, BoringSSL_SHA512) {
    auto dk = hmac::pbkdf2("passwordPASSWORDpassword",
                           "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                           4096, 64, hmac::Pbkdf2Hash::Sha512);
    std::string hex = hmac::to_hex(std::string(dk.begin(), dk.end()));
    EXPECT_EQ(hex,
              "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8");
}

TEST(PBKDF2Test, OpenSSLRandom) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto prf : {hmac::Pbkdf2Hash::Sha1, hmac::Pbkdf2Hash::Sha256, hmac::Pbkdf2Hash::Sha512}) {
        std::vector<uint8_t> pwd(16), salt(16);
        for (int i = 0; i < 2; ++i) {
            for (auto &x : pwd) x = static_cast<uint8_t>(dist(gen));
            for (auto &x : salt) x = static_cast<uint8_t>(dist(gen));
            size_t dk_len = (prf == hmac::Pbkdf2Hash::Sha1) ? 20 : 32;
            auto ours = hmac::pbkdf2(pwd, salt, 1000, dk_len, prf);
            std::vector<uint8_t> ref(dk_len);
            const EVP_MD* md = nullptr;
            switch (prf) {
                case hmac::Pbkdf2Hash::Sha1: md = EVP_sha1(); break;
                case hmac::Pbkdf2Hash::Sha256: md = EVP_sha256(); break;
                case hmac::Pbkdf2Hash::Sha512: md = EVP_sha512(); break;
            }
            ASSERT_TRUE(PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(pwd.data()), pwd.size(),
                                          salt.data(), salt.size(), 1000, md, dk_len, ref.data()));
            EXPECT_TRUE(hmac::constant_time_equals(ours, ref));
        }
    }
}

TEST(HKDFTest, RFC5869Case1) {
    std::vector<uint8_t> ikm(22, 0x0b);
    auto salt = from_hex("000102030405060708090a0b0c");
    auto info = from_hex("f0f1f2f3f4f5f6f7f8f9");
    auto prk = hmac::hkdf_extract_sha256(ikm, salt);
    std::string prk_hex = hmac::to_hex(std::string(prk.begin(), prk.end()));
    EXPECT_EQ(prk_hex, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    auto okm = hmac::hkdf_expand_sha256(prk, info, 42);
    std::string okm_hex = hmac::to_hex(std::string(okm.begin(), okm.end()));
    EXPECT_EQ(okm_hex,
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

TEST(PBKDF2Test, WithPepper) {
    std::string password = "secret";
    std::string pepper = "server";
    std::vector<uint8_t> salt_vec(16, 0x03);
    std::string salt(salt_vec.begin(), salt_vec.end());
    auto dk1 = hmac::pbkdf2_with_pepper(password, salt, pepper, 1000, 32);
    auto inner = hmac::get_hmac(pepper, password, hmac::TypeHash::SHA256, false);
    std::vector<uint8_t> inner_vec(inner.begin(), inner.end());
    auto dk2 = hmac::pbkdf2(inner_vec, salt_vec, 1000, 32, hmac::Pbkdf2Hash::Sha256);
    EXPECT_TRUE(hmac::constant_time_equals(dk1, dk2));
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

TEST(TotpTimeErrorTest, NegativeTimeThrows) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = 0;
    EXPECT_THROW(hmac::get_totp_code(key), std::runtime_error);
    mock_time_value = 0;
    mock_errno_value = 0;
}

TEST(TotpTimeErrorTest, NegativeTimeThrowsErrno) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = EINVAL;
    EXPECT_THROW(hmac::get_totp_code(key), std::runtime_error);
    mock_errno_value = 0;
    mock_time_value = 0;
}

TEST(TotpTimeErrorTest, ValidityNegativeTimeThrows) {
    const std::string key = "12345";
    mock_time_value = static_cast<std::time_t>(-1);
    mock_errno_value = 0;
    EXPECT_THROW(
        hmac::is_totp_token_valid(0, key.data(), key.size(), 30, 6, hmac::TypeHash::SHA1),
        std::runtime_error);
    mock_time_value = 0;
    mock_errno_value = 0;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

