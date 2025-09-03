/*
    sha1.cpp - source code of
 
    ============
    SHA-1 in C++
    ============
 
    100% Public Domain.
 
    Original C Code
        -- Steve Reid <steve@edmweb.com>
    Small changes to fit into bglibs
        -- Bruce Guenter <bruce@untroubled.org>
    Translation to simpler C++ Code
        -- Volker Grabsch <vog@notjusthosting.com>
*/

/* Based on: http://www.zedwood.com/article/cpp-sha1-function
 * Modified by NewYaroslav, 2025-04-15
 */

#include <cstdio>
#include <algorithm>
#include "sha1.hpp"

/* Help macros */
#define SHA1_ROL(value, bits) (((value) << (bits)) | (((value) & 0xffffffff) >> (32 - (bits))))
#define SHA1_BLK(i) (block[i&15] = SHA1_ROL(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i&15],1))
 
/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define SHA1_R0(v,w,x,y,z,i) z += ((w&(x^y))^y)     + block[i]    + 0x5a827999 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R1(v,w,x,y,z,i) z += ((w&(x^y))^y)     + SHA1_BLK(i) + 0x5a827999 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R2(v,w,x,y,z,i) z += (w^x^y)           + SHA1_BLK(i) + 0x6ed9eba1 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R3(v,w,x,y,z,i) z += (((w|x)&y)|(w&x)) + SHA1_BLK(i) + 0x8f1bbcdc + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
#define SHA1_R4(v,w,x,y,z,i) z += (w^x^y)           + SHA1_BLK(i) + 0xca62c1d6 + SHA1_ROL(v,5); w=SHA1_ROL(w,30);
 
namespace hmac_hash {
    
    void SHA1::init() {
        // SHA1 initialization constants
        m_h[0] = 0x67452301;
        m_h[1] = 0xefcdab89;
        m_h[2] = 0x98badcfe;
        m_h[3] = 0x10325476;
        m_h[4] = 0xc3d2e1f0;
     
        // Reset counters
        m_transforms = 0;
        m_buffer.clear();
    }
    
    void SHA1::update(const uint8_t *message, size_t length) {
        size_t offset = 0;

        // Fill buffer if it has existing bytes
        if (!m_buffer.empty()) {
            size_t to_copy = std::min(BLOCK_SIZE - m_buffer.size(), length);
            m_buffer.insert(m_buffer.end(), message, message + to_copy);
            offset += to_copy;

            if (m_buffer.size() == BLOCK_SIZE) {
                uint32_t block[16];
                buffer_to_block(m_buffer.data(), block);
                transform(block);
                m_buffer.clear();
            }
        }

        // Process full blocks directly from message
        while (offset + BLOCK_SIZE <= length) {
            uint32_t block[16];
            buffer_to_block(message + offset, block);
            transform(block);
            offset += BLOCK_SIZE;
        }

        // Store remaining bytes in buffer
        m_buffer.insert(m_buffer.end(), message + offset, message + length);
    }

    void SHA1::finish(uint8_t *digest) {
        // Total number of hashed bits
        uint64_t total_bits = (m_transforms * BLOCK_SIZE + m_buffer.size()) * 8;

        // Padding: append 0x80 byte
        m_buffer.push_back(0x80);
        while (m_buffer.size() % BLOCK_SIZE != (BLOCK_SIZE - 8)) {
            m_buffer.push_back(0x00);
        }

        // Append length in big-endian format (64-bit total_bits)
        for (int i = 7; i >= 0; --i) {
            m_buffer.push_back(static_cast<uint8_t>((total_bits >> (i * 8)) & 0xFF));
        }

        // Process all remaining full blocks
        for (size_t i = 0; i < m_buffer.size(); i += BLOCK_SIZE) {
            uint32_t block[16];
            buffer_to_block(m_buffer.data() + i, block);
            transform(block);
        }

        // Produce final digest (big-endian 32-bit words -> bytes)
        for (size_t i = 0; i < DIGEST_INTS; ++i) {
            digest[i * 4 + 0] = static_cast<uint8_t>((m_h[i] >> 24) & 0xFF);
            digest[i * 4 + 1] = static_cast<uint8_t>((m_h[i] >> 16) & 0xFF);
            digest[i * 4 + 2] = static_cast<uint8_t>((m_h[i] >>  8) & 0xFF);
            digest[i * 4 + 3] = static_cast<uint8_t>((m_h[i] >>  0) & 0xFF);
        }
    }

    // Hash a single 512-bit block. This is the core of the algorithm.
    void SHA1::transform(uint32_t *block) {
        uint32_t a = m_h[0];
        uint32_t b = m_h[1];
        uint32_t c = m_h[2];
        uint32_t d = m_h[3];
        uint32_t e = m_h[4];

        // 4 rounds of 20 operations each. Loop unrolled
        SHA1_R0(a,b,c,d,e, 0);
        SHA1_R0(e,a,b,c,d, 1);
        SHA1_R0(d,e,a,b,c, 2);
        SHA1_R0(c,d,e,a,b, 3);
        SHA1_R0(b,c,d,e,a, 4);
        SHA1_R0(a,b,c,d,e, 5);
        SHA1_R0(e,a,b,c,d, 6);
        SHA1_R0(d,e,a,b,c, 7);
        SHA1_R0(c,d,e,a,b, 8);
        SHA1_R0(b,c,d,e,a, 9);
        SHA1_R0(a,b,c,d,e,10);
        SHA1_R0(e,a,b,c,d,11);
        SHA1_R0(d,e,a,b,c,12);
        SHA1_R0(c,d,e,a,b,13);
        SHA1_R0(b,c,d,e,a,14);
        SHA1_R0(a,b,c,d,e,15);
        SHA1_R1(e,a,b,c,d,16);
        SHA1_R1(d,e,a,b,c,17);
        SHA1_R1(c,d,e,a,b,18);
        SHA1_R1(b,c,d,e,a,19);
        SHA1_R2(a,b,c,d,e,20);
        SHA1_R2(e,a,b,c,d,21);
        SHA1_R2(d,e,a,b,c,22);
        SHA1_R2(c,d,e,a,b,23);
        SHA1_R2(b,c,d,e,a,24);
        SHA1_R2(a,b,c,d,e,25);
        SHA1_R2(e,a,b,c,d,26);
        SHA1_R2(d,e,a,b,c,27);
        SHA1_R2(c,d,e,a,b,28);
        SHA1_R2(b,c,d,e,a,29);
        SHA1_R2(a,b,c,d,e,30);
        SHA1_R2(e,a,b,c,d,31);
        SHA1_R2(d,e,a,b,c,32);
        SHA1_R2(c,d,e,a,b,33);
        SHA1_R2(b,c,d,e,a,34);
        SHA1_R2(a,b,c,d,e,35);
        SHA1_R2(e,a,b,c,d,36);
        SHA1_R2(d,e,a,b,c,37);
        SHA1_R2(c,d,e,a,b,38);
        SHA1_R2(b,c,d,e,a,39);
        SHA1_R3(a,b,c,d,e,40);
        SHA1_R3(e,a,b,c,d,41);
        SHA1_R3(d,e,a,b,c,42);
        SHA1_R3(c,d,e,a,b,43);
        SHA1_R3(b,c,d,e,a,44);
        SHA1_R3(a,b,c,d,e,45);
        SHA1_R3(e,a,b,c,d,46);
        SHA1_R3(d,e,a,b,c,47);
        SHA1_R3(c,d,e,a,b,48);
        SHA1_R3(b,c,d,e,a,49);
        SHA1_R3(a,b,c,d,e,50);
        SHA1_R3(e,a,b,c,d,51);
        SHA1_R3(d,e,a,b,c,52);
        SHA1_R3(c,d,e,a,b,53);
        SHA1_R3(b,c,d,e,a,54);
        SHA1_R3(a,b,c,d,e,55);
        SHA1_R3(e,a,b,c,d,56);
        SHA1_R3(d,e,a,b,c,57);
        SHA1_R3(c,d,e,a,b,58);
        SHA1_R3(b,c,d,e,a,59);
        SHA1_R4(a,b,c,d,e,60);
        SHA1_R4(e,a,b,c,d,61);
        SHA1_R4(d,e,a,b,c,62);
        SHA1_R4(c,d,e,a,b,63);
        SHA1_R4(b,c,d,e,a,64);
        SHA1_R4(a,b,c,d,e,65);
        SHA1_R4(e,a,b,c,d,66);
        SHA1_R4(d,e,a,b,c,67);
        SHA1_R4(c,d,e,a,b,68);
        SHA1_R4(b,c,d,e,a,69);
        SHA1_R4(a,b,c,d,e,70);
        SHA1_R4(e,a,b,c,d,71);
        SHA1_R4(d,e,a,b,c,72);
        SHA1_R4(c,d,e,a,b,73);
        SHA1_R4(b,c,d,e,a,74);
        SHA1_R4(a,b,c,d,e,75);
        SHA1_R4(e,a,b,c,d,76);
        SHA1_R4(d,e,a,b,c,77);
        SHA1_R4(c,d,e,a,b,78);
        SHA1_R4(b,c,d,e,a,79);
     
        // Add the working vars back into m_h
        m_h[0] += a;
        m_h[1] += b;
        m_h[2] += c;
        m_h[3] += d;
        m_h[4] += e;
     
        // Count the number of transformations
        m_transforms++;
    }
     
    void SHA1::buffer_to_block(const uint8_t* buffer, uint32_t* block) {
        for (size_t i = 0; i < BLOCK_INTS; ++i) {
            block[i] =
                (static_cast<uint32_t>(buffer[4 * i + 0]) << 24) |
                (static_cast<uint32_t>(buffer[4 * i + 1]) << 16) |
                (static_cast<uint32_t>(buffer[4 * i + 2]) << 8)  |
                (static_cast<uint32_t>(buffer[4 * i + 3]) << 0);
        }
    }

    void sha1(const void* data, size_t length, uint8_t* digest) {
        hmac_hash::SHA1 ctx;
        ctx.init();
        ctx.update(reinterpret_cast<const uint8_t*>(data), length);
        ctx.finish(digest);
    }
    
    std::vector<uint8_t> sha1(const void* data, size_t length) {
        std::vector<uint8_t> digest(hmac_hash::SHA1::DIGEST_SIZE);
        hmac_hash::SHA1 ctx;
        ctx.init();
        ctx.update(reinterpret_cast<const uint8_t*>(data), length);
        ctx.finish(digest.data());
        return digest;
    }

    std::string sha1(const std::string &input) {
        uint8_t digest[hmac_hash::SHA1::DIGEST_SIZE];
        std::fill(digest, digest + hmac_hash::SHA1::DIGEST_SIZE, '\0');

        hmac_hash::SHA1 ctx;
        ctx.init();
        ctx.update(reinterpret_cast<const uint8_t*>(input.data()), input.length());
        ctx.finish(digest);

        char buf[2 * hmac_hash::SHA1::DIGEST_SIZE + 1];
        std::fill(buf, buf + (2 * hmac_hash::SHA1::DIGEST_SIZE + 1), '\0');
        for(size_t i = 0; i < hmac_hash::SHA1::DIGEST_SIZE; ++i) {
            std::snprintf(buf + i * 2, sizeof(buf) - i * 2, "%02x", digest[i]);
        }
        return std::string(buf, (2 * hmac_hash::SHA1::DIGEST_SIZE));
    }
}