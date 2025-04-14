/*
 * Updated to C++, zedwood.com 2012
 * Based on Olivier Gay's version
 * See Modified BSD License below:
 *
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Issue date:  04/30/2005
 * http://www.ouah.org/ogay/sha2/
 *
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Оригинал кода: http://www.zedwood.com/article/cpp-sha512-function
 * Исправления: 18.06.2020 Elektro Yar
 */

#include <cstring>
#include <fstream>
#include "sha512.hpp"

#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA512_F1(x) (SHA2_ROTR(x, 28) ^ SHA2_ROTR(x, 34) ^ SHA2_ROTR(x, 39))
#define SHA512_F2(x) (SHA2_ROTR(x, 14) ^ SHA2_ROTR(x, 18) ^ SHA2_ROTR(x, 41))
#define SHA512_F3(x) (SHA2_ROTR(x,  1) ^ SHA2_ROTR(x,  8) ^ SHA2_SHFR(x,  7))
#define SHA512_F4(x) (SHA2_ROTR(x, 19) ^ SHA2_ROTR(x, 61) ^ SHA2_SHFR(x,  6))
#define SHA2_UNPACK32(x, str)                 \
{                                             \
    *((str) + 3) = (uint8_t) ((x)      );       \
    *((str) + 2) = (uint8_t) ((x) >>  8);       \
    *((str) + 1) = (uint8_t) ((x) >> 16);       \
    *((str) + 0) = (uint8_t) ((x) >> 24);       \
}
#define SHA2_UNPACK64(x, str)                 \
{                                             \
    *((str) + 7) = (uint8_t) ((x)      );       \
    *((str) + 6) = (uint8_t) ((x) >>  8);       \
    *((str) + 5) = (uint8_t) ((x) >> 16);       \
    *((str) + 4) = (uint8_t) ((x) >> 24);       \
    *((str) + 3) = (uint8_t) ((x) >> 32);       \
    *((str) + 2) = (uint8_t) ((x) >> 40);       \
    *((str) + 1) = (uint8_t) ((x) >> 48);       \
    *((str) + 0) = (uint8_t) ((x) >> 56);       \
}
#define SHA2_PACK64(str, x)                   \
{                                             \
    *(x) =   ((uint64_t) *((str) + 7)      )    \
           | ((uint64_t) *((str) + 6) <<  8)    \
           | ((uint64_t) *((str) + 5) << 16)    \
           | ((uint64_t) *((str) + 4) << 24)    \
           | ((uint64_t) *((str) + 3) << 32)    \
           | ((uint64_t) *((str) + 2) << 40)    \
           | ((uint64_t) *((str) + 1) << 48)    \
           | ((uint64_t) *((str) + 0) << 56);   \
}

namespace hmac_hash {
    const uint64_t SHA512::sha512_k[80] = //ULL = uint64_t
                {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
                 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
                 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
                 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
                 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
                 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
                 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
                 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
                 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
                 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
                 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
                 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
                 0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
                 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
                 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
                 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
                 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
                 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
                 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
                 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
                 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
                 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
                 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
                 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
                 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
                 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
                 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
                 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
                 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
                 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
                 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
                 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
                 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
                 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
                 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
                 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
                 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
                 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
                 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
                 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

    void SHA512::transform(const uint8_t *message, size_t block_nb) {
        uint64_t w[80];
        uint64_t wv[8];
        uint64_t t1, t2;
        const uint8_t *sub_block;
        size_t i, j;
        for(i = 0; i < block_nb; ++i) {
            sub_block = message + (i << 7);
            for(j = 0; j < 16; ++j) {
                SHA2_PACK64(&sub_block[j << 3], &w[j]);
            }
            for(j = 16; j < 80; ++j) {
                w[j] =  SHA512_F4(w[j -  2]) + w[j -  7] + SHA512_F3(w[j - 15]) + w[j - 16];
            }
            for(j = 0; j < 8; ++j) {
                wv[j] = m_h[j];
            }
            for(j = 0; j < 80; ++j) {
                t1 = wv[7] + SHA512_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                    + sha512_k[j] + w[j];
                t2 = SHA512_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
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
        m_h[0] = 0x6a09e667f3bcc908ULL;
        m_h[1] = 0xbb67ae8584caa73bULL;
        m_h[2] = 0x3c6ef372fe94f82bULL;
        m_h[3] = 0xa54ff53a5f1d36f1ULL;
        m_h[4] = 0x510e527fade682d1ULL;
        m_h[5] = 0x9b05688c2b3e6c1fULL;
        m_h[6] = 0x1f83d9abfb41bd6bULL;
        m_h[7] = 0x5be0cd19137e2179ULL;
        m_len = 0;
        m_tot_len = 0;
    }

    void SHA512::update(const uint8_t *message, size_t length) {
        size_t block_nb;
        size_t new_len, rem_len, tmp_len;
        const uint8_t *shifted_message;
        tmp_len = SHA384_512_BLOCK_SIZE - m_len;
        rem_len = length < tmp_len ? length : tmp_len;
        memcpy(&m_block[m_len], message, rem_len);
        if((m_len + length) < SHA384_512_BLOCK_SIZE) {
            m_len += length;
            return;
        }
        new_len = length - rem_len;
        block_nb = new_len / SHA384_512_BLOCK_SIZE;
        shifted_message = message + rem_len;
        transform(m_block, 1);
        transform(shifted_message, block_nb);
        rem_len = new_len % SHA384_512_BLOCK_SIZE;
        memcpy(m_block, &shifted_message[block_nb << 7], rem_len);
        m_len = rem_len;
        m_tot_len += (block_nb + 1) << 7;
    }

    void SHA512::finish(uint8_t *digest) {
        size_t block_nb;
        size_t pm_len;
        size_t len_b;
        size_t i;
        block_nb = (1 + ((SHA384_512_BLOCK_SIZE - 17) 
			< (m_len % SHA384_512_BLOCK_SIZE)));
        len_b = (m_tot_len + m_len) << 3;
        pm_len = block_nb << 7;
        memset(m_block + m_len, 0, pm_len - m_len);
        m_block[m_len] = 0x80;
        SHA2_UNPACK32(len_b, m_block + pm_len - 4);
        transform(m_block, block_nb);
        for(i = 0 ; i < 8; ++i) {
            SHA2_UNPACK64(m_h[i], &digest[i << 3]);
        }
    }
	
	void sha512(const void* data, size_t length, uint8_t* digest) {
        hmac_hash::SHA512 ctx;
        ctx.init();
        ctx.update(reinterpret_cast<const uint8_t*>(data), length);
        ctx.finish(digest);
    }
	
	std::vector<uint8_t> sha512(const void* data, size_t length) {
        std::vector<uint8_t> digest(hmac_hash::SHA512::DIGEST_SIZE);
        hmac_hash::SHA512 ctx;
        ctx.init();
        ctx.update(reinterpret_cast<const uint8_t*>(data), length);
        ctx.finish(digest.data());
        return digest;
    }

    std::string sha512(const std::string &input) {
        uint8_t digest[hmac_hash::SHA512::DIGEST_SIZE];
        std::fill(digest, digest + hmac_hash::SHA512::DIGEST_SIZE, '\0');
        hmac_hash::SHA512 ctx;
        ctx.init();
        ctx.update((uint8_t*)input.c_str(), input.length());
        ctx.finish(digest);

        char buf[2 * hmac_hash::SHA512::DIGEST_SIZE + 1];
        std::fill(buf, buf + (2 * hmac_hash::SHA512::DIGEST_SIZE + 1), '\0');
        for(size_t i = 0; i < hmac_hash::SHA512::DIGEST_SIZE; ++i){
            sprintf(buf + i * 2, "%02x", digest[i]);
        }
        return std::string(buf, (2 * hmac_hash::SHA512::DIGEST_SIZE));
    }
}
