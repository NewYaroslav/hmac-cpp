//+------------------------------------------------------------------+
//|                                                   hmac_utils.mqh |
//|                                      Copyright 2025, NewYaroslav |
//|                                   https://github.com/NewYaroslav |
//+------------------------------------------------------------------+
#ifndef _HMAC_TIMED_TOKEN_MQH_INCLUDED
#define _HMAC_TIMED_TOKEN_MQH_INCLUDED

#include "hmac.mqh"

namespace hmac {

    /// \brief Generates a time-based HMAC-SHA256 token
    /// \param key Secret key used for HMAC
    /// \param interval_sec Interval in seconds that defines token rotation. Default is 60 seconds
    /// \param hash_type Hash function to use. Default is SHA256
    /// \return Hex-encoded HMAC-SHA256 of the rounded time value
    string generate_time_token(const string &key, int interval_sec = 60, hmac::TypeHash hash_type = hmac::TypeHash::SHA256) {
       datetime now = TimeGMT();
       datetime rounded = (now / interval_sec) * interval_sec;
       return hmac::get_hmac(key, IntegerToString(rounded), hash_type);
    }
    
    /// \brief Validates a time-based HMAC-SHA256 token with ±1 interval tolerance
    /// \param token Token received from the client
    /// \param key Secret key used for HMAC
    /// \param interval_sec Interval in seconds that defines token rotation. Default is 60 seconds
    /// \param hash_type Hash function to use. Default is SHA256
    /// \return true if the token is valid within the ±1 interval range; false otherwise
    bool is_token_valid(const string &token, const string &key, int interval_sec = 60, hmac::TypeHash hash_type = hmac::TypeHash::SHA256) {
        datetime now = TimeGMT();
        datetime rounded = (now / interval_sec) * interval_sec;
        if (token == get_hmac(key, IntegerToString(rounded), hash_type)) return true;
        if (token == get_hmac(key, IntegerToString(rounded - interval_sec), hash_type)) return true;
        if (token == get_hmac(key, IntegerToString(rounded + interval_sec), hash_type)) return true;
        return false;
    }
    
    /// \brief Generates a time-based HMAC-SHA256 token with fingerprint binding
    /// \param key Secret key used for HMAC
    /// \param fingerprint Unique client identifier (e.g., device ID or session hash)
    /// \param interval_sec Interval in seconds that defines token rotation. Default is 60 seconds
    /// \param hash_type Hash function to use. Default is SHA256
    /// \return Hex-encoded HMAC-SHA256 of the concatenated timestamp and fingerprint
    string generate_time_token(const string &key, const string &fingerprint, int interval_sec = 60, hmac::TypeHash hash_type = hmac::TypeHash::SHA256) {
       datetime now = TimeGMT();
       datetime rounded = (now / interval_sec) * interval_sec;
       string payload = IntegerToString(rounded) + "|" + fingerprint;
       return hmac::get_hmac(key, payload, hash_type);
    }
    
    /// \brief Validates a fingerprint-bound HMAC-SHA256 token with ±1 interval tolerance
    /// \param token Token received from the client
    /// \param key Secret key used for HMAC
    /// \param fingerprint Unique client identifier (e.g., device ID or session hash)
    /// \param interval_sec Interval in seconds that defines token rotation. Default is 60 seconds
    /// \param hash_type Hash function to use. Default is SHA256
    /// \return true if the token is valid within the ±1 interval range; false otherwise
    bool is_token_valid(const string &token, const string &key, const string &fingerprint, int interval_sec = 60, hmac::TypeHash hash_type = hmac::TypeHash::SHA256) {
        datetime now = TimeGMT();
        datetime rounded = (now / interval_sec) * interval_sec;
        string prefix = "|" + fingerprint;
        string payload = IntegerToString(rounded) + prefix;
        if (token == get_hmac(key, payload, hash_type)) return true;
        payload = IntegerToString(rounded - interval_sec) + prefix;
        if (token == get_hmac(key, payload, hash_type)) return true;
        payload = IntegerToString(rounded + interval_sec) + prefix;
        if (token == get_hmac(key, payload, hash_type)) return true;
        return false;
    }
    
    /// \brief Generates a unique fingerprint of the client based on available terminal and account info
    /// \return String representing the client fingerprint
    string generate_client_fingerprint() {
        string fingerprint;
        StringConcatenate(fingerprint, 
            AccountInfoInteger(ACCOUNT_LOGIN), "|", 
            AccountInfoString(ACCOUNT_COMPANY), "|", 
            TerminalInfoString(TERMINAL_COMPANY), "|", 
            TerminalInfoString(TERMINAL_NAME), "|",
            TerminalInfoString(TERMINAL_OS_VERSION), "|",
            TerminalInfoString(TERMINAL_PATH));
        return fingerprint;
    }

};

#endif // _HMAC_TIMED_TOKEN_MQH_INCLUDED