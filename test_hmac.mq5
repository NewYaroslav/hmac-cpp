#include <hmac-cpp\hmac.mqh>
#include <hmac-cpp\hmac_utils.mqh>

void print_section(const string &title) {
   Print("=== ", title, " ===");
}

void OnStart() {
    string data = "grape";
    string key = "12345";
    
    // SHA256
    print_section("SHA256");
    string sha256_output_1 = hmac::get_hash(data, hmac::TypeHash::SHA256);
    string sha256_output_2 = hmac_hash::sha256(data);
    Print("sha256('", data, "') = ", sha256_output_1);
    Print("sha256('", data, "') = ", sha256_output_2);
    Print("Expected: 0f78fcc486f5315418fbf095e71c0675ee07d318e5ac4d150050cd8e57966496\n");
    
    // SHA512
    print_section("SHA512");
    string sha512_output_1 = hmac::get_hash(data, hmac::TypeHash::SHA512);
    string sha512_output_2 = hmac_hash::sha512(data);
    Print("sha512('", data, "') = ", sha512_output_1);
    Print("sha512('", data, "') = ", sha512_output_2);
    Print("Expected: 9375d1abdb644a01955bccad12e2f5c2bd8a3e226187e548d99c559a99461453b980123746753d07c169c22a5d9cc75cb158f0e8d8c0e713559775b5e1391fc4\n");
    
    // to_hex
    print_section("to_hex");
    string hex_output = hmac::to_hex("012345");
    Print("to_hex(\"012345\") = ", hex_output, "\n");
    
    // HMAC-SHA256
    print_section("HMAC-SHA256");
    string hmac_sha256 = hmac::get_hmac(key, data, hmac::TypeHash::SHA256);
    Print("HMAC('", key, "', '", data, "', SHA256) = ", hmac_sha256);
    Print("Expected: 7632ac2e8ddedaf4b3e7ab195fefd17571c37c970e02e169195a158ef59e53ca\n");
    
    // HMAC-SHA512
    print_section("HMAC-SHA512");
    string hmac_sha512 = hmac::get_hmac(key, data, hmac::TypeHash::SHA512);
    Print("HMAC('", key, "', '", data, "', SHA512) = ", hmac_sha512);
    Print("Expected: c54ddf9647a949d0df925a1c1f8ba1c9d721a671c396fde1062a71f9f7ffae5dc10f6be15be63bb0363d051365e23f890368c54828497b9aef2eb2fc65b633e6\n");
    
    // HMAC-SHA512 uppercase hex
    print_section("HMAC-SHA512 (uppercase)");
    string hmac_sha512_upper = hmac::get_hmac(key, data, hmac::TypeHash::SHA512, true);
    Print("HMAC('", key, "', '", data, "', SHA512, hex=true, upper=true) = ", hmac_sha512_upper);
    
    // HMAC-TIMED TOKEN
    print_section("HMAC-TIMED TOKEN");
    string secret_key = "super-secret-key";
    string time_token = hmac::generate_time_token(secret_key, 60);
    Print("Time        : ", TimeToString(TimeLocal(), TIME_MINUTES));
    Print("Token       : ", time_token);
    Print("Is valid    : ", hmac::is_token_valid(time_token, secret_key, 60));
    
    // HMAC-TIMED TOKEN with fingerprint
    print_section("HMAC-TIMED TOKEN (with fingerprint)");
    string fingerprint = hmac::generate_client_fingerprint();
    string time_token_fp = hmac::generate_time_token(secret_key, fingerprint, 60);
    Print("Fingerprint : ", fingerprint);
    Print("Time        : ", TimeToString(TimeLocal(), TIME_MINUTES));
    Print("Token       : ", time_token_fp);
    Print("Is valid    : ", hmac::is_token_valid(time_token_fp, secret_key, fingerprint, 60));
}