//+------------------------------------------------------------------+
//|                                                       sha256.mqh |
//|                                      Copyright 2025, NewYaroslav |
//|                                   https://github.com/NewYaroslav |
//+------------------------------------------------------------------+

// Based on: http://www.zedwood.com/article/cpp-sha256-function

#ifndef _HMAC_SHA256_MQH_INCLUDED
#define _HMAC_SHA256_MQH_INCLUDED

#define SHA256_SHFR(x, n)    (x >> n)
#define SHA256_ROTR(x, n)   ((x >> n) | (x << (32 - n)))
#define SHA256_ROTL(x, n)   ((x << n) | (x >> (32 - n)))
#define SHA256_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA256_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA256_ROTR(x,  2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22))
#define SHA256_F2(x) (SHA256_ROTR(x,  6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25))
#define SHA256_F3(x) (SHA256_ROTR(x,  7) ^ SHA256_ROTR(x, 18) ^ SHA256_SHFR(x,  3))
#define SHA256_F4(x) (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ SHA256_SHFR(x, 10))

#define SHA256_DIGEST_SIZE    32
#define SHA224_256_BLOCK_SIZE 64

namespace hmac_hash {

    /// \brief Class for computing SHA256 hash
    class SHA256 {
    public:

        /// \brief Initializes SHA256 context
        void init();

        /// \brief Updates SHA256 with new message data
        /// \param message Pointer to input data
        /// \param length Length of input data
        void update(const uchar &message[], int length);

        /// \brief Finalizes SHA256 and produces the hash
        /// \param digest Output buffer of size DIGEST_SIZE
        void finish(uchar &digest[]);

    protected:
        void transform(const uchar &message[], int block_nb);
        ulong m_tot_len;
        int m_len;
        uchar m_block[2 * SHA224_256_BLOCK_SIZE];
        uint m_h[8];
    };

    const uint SHA256_K[64] =
        {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
         0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
         0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
         0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    void SHA256::transform(const uchar &message[], int block_nb) {
        uint w[64];
        uint wv[8];
        uint t1, t2;
        int i;
        int j;
        for(i = 0; i < block_nb; ++i) {
            int base = i * SHA224_256_BLOCK_SIZE;
            
            for (j = 0; j < 16; ++j) {
                int idx = base + j * 4;
                w[j] =
                    ((uint)message[idx + 0] << 24) |
                    ((uint)message[idx + 1] << 16) |
                    ((uint)message[idx + 2] << 8) |
                    ((uint)message[idx + 3]);
            }
            
            for (j = 16; j < 64; ++j) {
                w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];
            }
            for(j = 0; j < 8; ++j) {
                wv[j] = m_h[j];
            }
            for(j = 0; j < 64; ++j) {
                t1 = wv[7] + SHA256_F2(wv[4]) + SHA256_CH(wv[4], wv[5], wv[6]) + SHA256_K[j] + w[j];
                t2 = SHA256_F1(wv[0]) + SHA256_MAJ(wv[0], wv[1], wv[2]);
                wv[7] = wv[6];
                wv[6] = wv[5];
                wv[5] = wv[4];
                wv[4] = wv[3] + t1;
                wv[3] = wv[2];
                wv[2] = wv[1];
                wv[1] = wv[0];
                wv[0] = t1 + t2;
            }
            for(j = 0; j < 8; ++j) {
                m_h[j] += wv[j];
            }
        }
    }

    void SHA256::init() {
        m_h[0] = 0x6a09e667;
        m_h[1] = 0xbb67ae85;
        m_h[2] = 0x3c6ef372;
        m_h[3] = 0xa54ff53a;
        m_h[4] = 0x510e527f;
        m_h[5] = 0x9b05688c;
        m_h[6] = 0x1f83d9ab;
        m_h[7] = 0x5be0cd19;
        m_len = 0;
        m_tot_len = 0;
    }

    void SHA256::update(const uchar &message[], int length) {
        int block_nb;
        int new_len, rem_len, tmp_len;
        tmp_len = SHA224_256_BLOCK_SIZE - m_len;
        rem_len = length < tmp_len ? length : tmp_len;
        ArrayCopy(m_block, message, m_len, 0, rem_len);
        if (m_len + length < SHA224_256_BLOCK_SIZE) {
            m_len += length;
            return;
        }
        new_len = length - rem_len;
        block_nb = new_len / SHA224_256_BLOCK_SIZE;
        uchar shifted_message[];
        ArrayResize(shifted_message, new_len);
        ArrayCopy(shifted_message, message, 0, rem_len, new_len);
        transform(m_block, 1);
        if (block_nb > 0) transform(shifted_message, block_nb);
        rem_len = new_len % SHA224_256_BLOCK_SIZE;
        ArrayCopy(m_block, shifted_message, 0, block_nb * SHA224_256_BLOCK_SIZE, rem_len);
        m_len = rem_len;
        m_tot_len += (ulong)(block_nb + 1) * SHA224_256_BLOCK_SIZE;
    }

    void SHA256::finish(uchar &digest[]) {
        int block_nb;
        int pm_len;
        ulong len_b;
        int i;
        block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9) < (m_len % SHA224_256_BLOCK_SIZE)));
        len_b = (m_tot_len + m_len) << 3;
        pm_len = block_nb * SHA224_256_BLOCK_SIZE;
        for (int k = m_len; k < pm_len; ++k) m_block[k] = 0;
        m_block[m_len] = 0x80;
        m_block[pm_len - 8] = (uchar)((len_b >> 56) & 0xFF);
        m_block[pm_len - 7] = (uchar)((len_b >> 48) & 0xFF);
        m_block[pm_len - 6] = (uchar)((len_b >> 40) & 0xFF);
        m_block[pm_len - 5] = (uchar)((len_b >> 32) & 0xFF);
        m_block[pm_len - 4] = (uchar)((len_b >> 24) & 0xFF);
        m_block[pm_len - 3] = (uchar)((len_b >> 16) & 0xFF);
        m_block[pm_len - 2] = (uchar)((len_b >> 8) & 0xFF);
        m_block[pm_len - 1] = (uchar)((len_b >> 0) & 0xFF);
        transform(m_block, block_nb);
        for(i = 0 ; i < 8; ++i) {
            int pos = i * 4;
            digest[pos + 0] = (uchar)((m_h[i] >> 24) & 0xFF);
            digest[pos + 1] = (uchar)((m_h[i] >> 16) & 0xFF);
            digest[pos + 2] = (uchar)((m_h[i] >> 8) & 0xFF);
            digest[pos + 3] = (uchar)((m_h[i] >> 0) & 0xFF);
        }
    }
    
    /// \brief Computes SHA256 hash of a byte array.
    /// \param digest Hash as a byte array.
    /// \param data Input byte array.
    void sha256(uchar &digest[], const uchar &data[]) {
        ArrayResize(digest, SHA256_DIGEST_SIZE);
        ArrayFill(digest, 0, SHA256_DIGEST_SIZE, 0);
        if (ArraySize(data) == 0) return;
        SHA256 ctx;
        ctx.init();
        ctx.update(data, ArraySize(data));
        ctx.finish(digest);
    }
    
    /// \brief Computes SHA256 hash of a string
    /// \param str Input string
    /// \return Hash as a binary string
    string sha256(const string &str) {
        uchar bytes[];
        StringToCharArray(str, bytes, 0, -1, CP_UTF8);
        int len = ArraySize(bytes);
        if (len > 0 && bytes[len - 1] == '\0') {
            len -= 1;
            ArrayResize(bytes, len);
        }

        uchar digest[];
        sha256(digest, bytes);
        string result;
        for(int i = 0; i < SHA256_DIGEST_SIZE; ++i) {
            result += StringFormat("%02x", digest[i]);
        }
        return result;
    }
}

#endif // _HMAC_SHA256_MQH_INCLUDED
