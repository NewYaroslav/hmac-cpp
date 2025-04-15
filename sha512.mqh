//+------------------------------------------------------------------+
//|                                                       sha512.mqh |
//|                                      Copyright 2025, NewYaroslav |
//|                                   https://github.com/NewYaroslav |
//+------------------------------------------------------------------+

// Based on: http://www.zedwood.com/article/cpp-sha512-function

#ifndef _HMAC_SHA512_MQH_INCLUDED
#define _HMAC_SHA512_MQH_INCLUDED

#define SHA512_SHFR(x, n)    (x >> n)
#define SHA512_ROTR(x, n)   ((x >> n) | (x << (64 - n)))
#define SHA512_ROTL(x, n)   ((x << n) | (x >> (64 - n)))
#define SHA512_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA512_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA512_F1(x) (SHA512_ROTR(x, 28) ^ SHA512_ROTR(x, 34) ^ SHA512_ROTR(x, 39))
#define SHA512_F2(x) (SHA512_ROTR(x, 14) ^ SHA512_ROTR(x, 18) ^ SHA512_ROTR(x, 41))
#define SHA512_F3(x) (SHA512_ROTR(x,  1) ^ SHA512_ROTR(x,  8) ^ SHA512_SHFR(x,  7))
#define SHA512_F4(x) (SHA512_ROTR(x, 19) ^ SHA512_ROTR(x, 61) ^ SHA512_SHFR(x,  6))

#define SHA512_DIGEST_SIZE      64 ///< Hash output size in bytes
#define SHA384_512_BLOCK_SIZE  128 ///< Block size in bytes

namespace hmac_hash {

    /// \brief SHA512 hashing class
    ///
    /// SHA-512 is the largest hash function in the SHA-2 family.
    /// It provides 256-bit security for digital signatures and hash-only applications.
    class SHA512 {
    public:

        /// \brief Initializes the SHA512 context
        void init();

        /// \brief Updates the SHA512 context with message data
        /// \param message Pointer to the input data
        /// \param length Length of the input data in bytes
        void update(const uchar &message[], int length);

        /// \brief Finalizes the SHA512 computation
        /// \param digest Output buffer of size DIGEST_SIZE
        void finish(uchar &digest[]);

    protected:
        void transform(const uchar &message[], int block_nb);
        int m_tot_len;
        int m_len;
        uchar m_block[2 * SHA384_512_BLOCK_SIZE];
        ulong m_h[8];
    };

    const ulong SHA512_K[80] =
        {0x428a2f98d728ae22, 0x7137449123ef65cd,
         0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
         0x3956c25bf348b538, 0x59f111f1b605d019,
         0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
         0xd807aa98a3030242, 0x12835b0145706fbe,
         0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
         0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
         0x9bdc06a725c71235, 0xc19bf174cf692694,
         0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
         0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
         0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
         0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
         0x983e5152ee66dfab, 0xa831c66d2db43210,
         0xb00327c898fb213f, 0xbf597fc7beef0ee4,
         0xc6e00bf33da88fc2, 0xd5a79147930aa725,
         0x06ca6351e003826f, 0x142929670a0e6e70,
         0x27b70a8546d22ffc, 0x2e1b21385c26c926,
         0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
         0x650a73548baf63de, 0x766a0abb3c77b2a8,
         0x81c2c92e47edaee6, 0x92722c851482353b,
         0xa2bfe8a14cf10364, 0xa81a664bbc423001,
         0xc24b8b70d0f89791, 0xc76c51a30654be30,
         0xd192e819d6ef5218, 0xd69906245565a910,
         0xf40e35855771202a, 0x106aa07032bbd1b8,
         0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
         0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
         0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
         0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
         0x748f82ee5defb2fc, 0x78a5636f43172f60,
         0x84c87814a1f0ab72, 0x8cc702081a6439ec,
         0x90befffa23631e28, 0xa4506cebde82bde9,
         0xbef9a3f7b2c67915, 0xc67178f2e372532b,
         0xca273eceea26619c, 0xd186b8c721c0c207,
         0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
         0x06f067aa72176fba, 0x0a637dc5a2c898a6,
         0x113f9804bef90dae, 0x1b710b35131c471b,
         0x28db77f523047d84, 0x32caab7b40c72493,
         0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
         0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
         0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
         
    void SHA512::transform(const uchar &message[], int block_nb) {
        ulong w[80];
        ulong wv[8];
        ulong t1, t2;
        int i, j;
        for(i = 0; i < block_nb; ++i) {
            int base = i * SHA384_512_BLOCK_SIZE;
            for (j = 0; j < 16; ++j) {
                int idx = base + j * 8;
                w[j] =
                    ((ulong)message[idx + 0] << 56) |
                    ((ulong)message[idx + 1] << 48) |
                    ((ulong)message[idx + 2] << 40) |
                    ((ulong)message[idx + 3] << 32) |
                    ((ulong)message[idx + 4] << 24) |
                    ((ulong)message[idx + 5] << 16) |
                    ((ulong)message[idx + 6] << 8)  |
                    ((ulong)message[idx + 7]);
            }
            for(j = 16; j < 80; ++j) {
                w[j] =  SHA512_F4(w[j -  2]) + w[j -  7] + SHA512_F3(w[j - 15]) + w[j - 16];
            }
            for(j = 0; j < 8; ++j) {
                wv[j] = m_h[j];
            }
            for(j = 0; j < 80; ++j) {
                t1 = wv[7] + SHA512_F2(wv[4]) + SHA512_CH(wv[4], wv[5], wv[6]) + SHA512_K[j] + w[j];
                t2 = SHA512_F1(wv[0]) + SHA512_MAJ(wv[0], wv[1], wv[2]);
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
         
    void SHA512::init() {
        m_h[0] = 0x6a09e667f3bcc908;
        m_h[1] = 0xbb67ae8584caa73b;
        m_h[2] = 0x3c6ef372fe94f82b;
        m_h[3] = 0xa54ff53a5f1d36f1;
        m_h[4] = 0x510e527fade682d1;
        m_h[5] = 0x9b05688c2b3e6c1f;
        m_h[6] = 0x1f83d9abfb41bd6b;
        m_h[7] = 0x5be0cd19137e2179;
        m_len = 0;
        m_tot_len = 0;
    }

    void SHA512::update(const uchar &message[], int length) {
        int block_nb;
        int new_len, rem_len, tmp_len;
        tmp_len = SHA384_512_BLOCK_SIZE - m_len;
        rem_len = (length < tmp_len) ? length : tmp_len;
        ArrayCopy(m_block, message, m_len, 0, rem_len);
        if ((m_len + length) < SHA384_512_BLOCK_SIZE) {
            m_len += length;
            return;
        }
        new_len = length - rem_len;
        block_nb = new_len / SHA384_512_BLOCK_SIZE;
        uchar shifted_message[];
        ArrayResize(shifted_message, new_len);
        ArrayCopy(shifted_message, message, 0, rem_len, new_len);
        transform(m_block, 1);
        if (block_nb > 0) transform(shifted_message, block_nb);
        rem_len = new_len % SHA384_512_BLOCK_SIZE;
        ArrayCopy(m_block, shifted_message, 0, block_nb * SHA384_512_BLOCK_SIZE, rem_len);
        m_len = rem_len;
        m_tot_len += (block_nb + 1) * SHA384_512_BLOCK_SIZE;
    }

    void SHA512::finish(uchar &digest[]) {
        int block_nb;
        int pm_len;
        int len_b;
        int i;
        block_nb = 1 + ((SHA384_512_BLOCK_SIZE - 17) < (m_len % SHA384_512_BLOCK_SIZE));
        len_b = (m_tot_len + m_len) << 3;
        pm_len = block_nb * SHA384_512_BLOCK_SIZE;
        for (int k = m_len; k < pm_len; ++k) m_block[k] = 0;
        m_block[m_len] = 0x80;
        m_block[pm_len - 4] = (uchar)((len_b >> 24) & 0xFF);
        m_block[pm_len - 3] = (uchar)((len_b >> 16) & 0xFF);
        m_block[pm_len - 2] = (uchar)((len_b >> 8) & 0xFF);
        m_block[pm_len - 1] = (uchar)((len_b >> 0) & 0xFF);
        transform(m_block, block_nb);
        for(i = 0 ; i < 8; ++i) {
            int pos = i * 8;
            digest[pos + 0] = (uchar)((m_h[i] >> 56) & 0xFF);
            digest[pos + 1] = (uchar)((m_h[i] >> 48) & 0xFF);
            digest[pos + 2] = (uchar)((m_h[i] >> 40) & 0xFF);
            digest[pos + 3] = (uchar)((m_h[i] >> 32) & 0xFF);
            digest[pos + 4] = (uchar)((m_h[i] >> 24) & 0xFF);
            digest[pos + 5] = (uchar)((m_h[i] >> 16) & 0xFF);
            digest[pos + 6] = (uchar)((m_h[i] >> 8)  & 0xFF);
            digest[pos + 7] = (uchar)((m_h[i] >> 0)  & 0xFF);
        }
    }

    /// \brief Computes SHA512 hash of a byte array.
    /// \param digest Hash as a byte array.
    /// \param data Input byte array.
    void sha512(uchar &digest[], const uchar &data[]) {
        ArrayResize(digest, SHA512_DIGEST_SIZE);
        ArrayFill(digest, 0, SHA512_DIGEST_SIZE, 0);
        if (ArraySize(data) == 0) return;
        SHA512 ctx;
        ctx.init();
        ctx.update(data, ArraySize(data));
        ctx.finish(digest);
    }

    /// \brief Computes SHA512 hash of a string
    /// \param str Input string
    /// \return Hash as a binary string
    string sha512(const string &str) {
        uchar bytes[];
        StringToCharArray(str, bytes, 0, -1, CP_UTF8);
        int len = ArraySize(bytes);
        if (len > 0 && bytes[len - 1] == '\0') {
            len -= 1;
            ArrayResize(bytes, len);
        }
        
        uchar digest[];
        sha512(digest, bytes);
        string result;
        for(int i = 0; i < SHA512_DIGEST_SIZE; ++i) {
            result += StringFormat("%02x", digest[i]);
        }
        return result;
    }
}

#endif // _HMAC_SHA512_MQH_INCLUDED
