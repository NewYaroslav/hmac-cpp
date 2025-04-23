//+------------------------------------------------------------------+
//|                                                         hmac.mqh |
//|                                      Copyright 2025, NewYaroslav |
//|                                   https://github.com/NewYaroslav |
//+------------------------------------------------------------------+
#ifndef _HMAC_MQH_INCLUDED
#define _HMAC_MQH_INCLUDED

#include "sha256.mqh"
#include "sha512.mqh"

namespace hmac {

    /// \brief Type of the hash function used
    enum TypeHash {
        HASH_SHA256 = 0, ///< Use SHA256
        HASH_SHA512 = 1, ///< Use SHA512
    };
    
    /// \brief Converts a byte array to hexadecimal string
    /// \param bytes Input byte array
    /// \param is_upper Flag for uppercase hex
    /// \return Hex string
    string to_hex(const uchar &bytes[], bool is_upper = false) {
        static const uchar lut[] = {
           '0','1','2','3','4','5','6','7','8','9',
           'a','b','c','d','e','f',
           '0','1','2','3','4','5','6','7','8','9',
           'A','B','C','D','E','F'
        };

        int len = ArraySize(bytes);
        if (len <= 0) return "";

        uchar output[];
        ArrayResize(output, 2 * len);

        int symbol_offset = is_upper ? 16 : 0;

        for (int i = 0; i < len; ++i) {
            uchar ch = bytes[i];
            int j = i * 2;
            output[j]     = lut[symbol_offset + (ch >> 4)];
            output[j + 1] = lut[symbol_offset + (ch & 0x0F)];
        }

        return CharArrayToString(output, 0, -1, CP_UTF8);
    }
    
    /// \brief Converts a string to hexadecimal format
    /// \param str Input string
    /// \param is_upper Flag for uppercase hex
    /// \return Hexadecimal string
    string to_hex(const string& str, bool is_upper = false) {
        uchar bytes[];
        StringToCharArray(str, bytes, 0, -1, CP_UTF8);
        return to_hex(bytes, is_upper);
    }
    
    /// \brief Computes hash of the input bytes
    /// \param digest Output buffer, resized automatically depending on hash type
    /// \param data Input bytes
    /// \param type Hash function type
    void calc_hash(uchar &digest[], const uchar &data[], TypeHash type) {
        switch(type) {
            case TypeHash::HASH_SHA256: {
                ArrayResize(digest, SHA256_DIGEST_SIZE);
                ArrayFill(digest, 0, SHA256_DIGEST_SIZE, 0);
                hmac_hash::SHA256 ctx;
                ctx.init();
                ctx.update(data, ArraySize(data));
                ctx.finish(digest);
                break;
            }
            case TypeHash::HASH_SHA512: {
                ArrayResize(digest, SHA512_DIGEST_SIZE);
                ArrayFill(digest, 0, SHA512_DIGEST_SIZE, 0);
                hmac_hash::SHA512 ctx;
                ctx.init();
                ctx.update(data, ArraySize(data));
                ctx.finish(digest);
                break;
            }
            default: break;
        };
    }

    /// \brief Computes hash of the input string
    /// \param str Input string
    /// \param type Hash function type
    /// \return Hash result
    string get_hash(const string &str, TypeHash type) {
        uchar bytes[];
        StringToCharArray(str, bytes, 0, -1, CP_UTF8);
        int len = ArraySize(bytes);
        if (len > 0 && bytes[len - 1] == '\0') len -= 1;
        ArrayResize(bytes, len);
        uchar digest[];
        calc_hash(digest, bytes, type);
        string hex;
        for(int i = 0; i < ArraySize(digest); ++i) {
            hex += StringFormat("%02x", digest[i]);
        }
        return hex;
    }

    /// \brief Computes HMAC
    /// \param digest HMAC result
    /// \param key_data Secret key
    /// \param msg_data Message
    /// \param type Hash function type
    void calc_hmac(uchar &digest[], const uchar &key_data[], const uchar &msg_data[], TypeHash type) {
        int block_size = 0;
        int digest_size = 0;
        switch(type) {
        case TypeHash::HASH_SHA256:
            block_size = SHA224_256_BLOCK_SIZE;
            digest_size = SHA256_DIGEST_SIZE;
            break;
        case TypeHash::HASH_SHA512:
            block_size = SHA384_512_BLOCK_SIZE;
            digest_size = SHA512_DIGEST_SIZE;
            break;
        default: return;
        };
        
        uchar key[];
        if (ArraySize(key_data) > block_size) {
            calc_hash(key, key_data, type);
        } else {
            ArrayResize(key, ArraySize(key_data));
            ArrayCopy(key, key_data);
        }
        
        if (ArraySize(key) < block_size) {
            int old_len = ArraySize(key);
            ArrayResize(key, block_size);
            ArrayFill(key, old_len, block_size - old_len, 0);
        }

        uchar ikeypad[];
        uchar okeypad[];
        ArrayResize(ikeypad, block_size + ArraySize(msg_data));
        ArrayResize(okeypad, block_size + digest_size);
        
        for(int i = 0; i < block_size; ++i) {
            ikeypad[i] = 0x36 ^ key[i];
            okeypad[i] = 0x5c ^ key[i];
        }
        
        // ikeypad + message
        ArrayCopy(ikeypad, msg_data, block_size, 0, ArraySize(msg_data));
        
        // inner hash
        uchar inner_hash[];
        calc_hash(inner_hash, ikeypad, type);

        // okeypad + inner hash
        ArrayCopy(okeypad, inner_hash, block_size, 0, digest_size);
        
        // final HMAC
        calc_hash(digest, okeypad, type);
    }

    /// \brief Computes HMAC and returns result in hexadecimal string
    /// \param key_str Secret key as string
    /// \param msg_str Message as string
    /// \param type Hash function type (e.g. SHA256 or SHA512)
    /// \param is_upper Whether to return hex in uppercase
    /// \return Hex string representing HMAC
    string get_hmac(const string& key_str, const string &msg_str, TypeHash type, bool is_upper = false) {
        uchar key_bytes[];
        uchar msg_bytes[];
        StringToCharArray(key_str, key_bytes, 0, -1, CP_UTF8);
        StringToCharArray(msg_str, msg_bytes, 0, -1, CP_UTF8);
        int len = ArraySize(key_bytes);
        if (len > 0 && key_bytes[len - 1] == '\0') ArrayResize(key_bytes, len - 1);
        len = ArraySize(msg_bytes);
        if (len > 0 && msg_bytes[len - 1] == '\0') ArrayResize(msg_bytes, len - 1);
        uchar hmac_bytes[];
        calc_hmac(hmac_bytes, key_bytes, msg_bytes, type);
        return to_hex(hmac_bytes, is_upper);
    }
}

#endif // _HMAC_MQH_INCLUDED