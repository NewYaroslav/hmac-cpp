/*
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
 
#ifndef _HMAC_SHA1_HPP_INCLUDED
#define _HMAC_SHA1_HPP_INCLUDED

#include <algorithm>
#include <string>
#include <vector>
#include <cstdint>

namespace hmac_hash {

    /// \brief Class for computing SHA1 hash
    class SHA1 {
    public:

        /// \brief Initializes SHA1 context
        void init();

        /// \brief Updates SHA1 with new message data
        /// \param message Pointer to input data
        /// \param length Length of input data
        void update(const uint8_t *message, size_t length);

        /// \brief Finalizes SHA1 and produces the hash
        /// \param digest Output buffer of size DIGEST_SIZE
        void finish(uint8_t *digest);

        static const size_t DIGEST_SIZE = (5 * 4);  ///< Digest size in bytes
        static const size_t BLOCK_SIZE  = (16 * 4); ///< Block size in bytes
        static const size_t DIGEST_INTS = 5;        ///< Number of 32bit integers per SHA1 digest
        static const size_t BLOCK_INTS  = 16;       ///< Number of 32bit integers per SHA1 block

    protected:
        void buffer_to_block(const uint8_t* buffer, uint32_t* block);
        void transform(uint32_t *block);
        uint32_t m_h[5];
        size_t m_transforms;
        std::vector<uint8_t> m_buffer;
    };
    
    /// \brief Computes sha1 hash of a raw byte buffer
    /// \param data Pointer to input data
    /// \param length Length of the input data
    /// \param digest Output buffer of size SHA1::DIGEST_SIZE
    void sha1(const void* data, size_t length, uint8_t* digest);

    /// \brief Computes SHA1 hash of a raw byte buffer
    /// \param data Pointer to input data
    /// \param length Length of the input data
    /// \return Vector containing the SHA1 digest
    std::vector<uint8_t> sha1(const void* data, size_t length);
    
    /// \brief Computes SHA1 hash of a string
    /// \param input Input string
    /// \return Hash as a binary string
    std::string sha1(const std::string &input);
    
    /// \brief Computes SHA1 hash of a vector of bytes
    /// \tparam T Type of the vector element (char or uint8_t)
    /// \param input Input vector
    /// \return Vector with SHA1 digest
    template<typename T>
    std::vector<uint8_t> sha1(const std::vector<T>& input) {
        static_assert(std::is_same<T, char>::value || std::is_same<T, uint8_t>::value,
                      "sha1(vector<T>) only supports vector<char> or vector<uint8_t>");

        uint8_t digest[hmac_hash::SHA1::DIGEST_SIZE];
        std::fill(digest, digest + hmac_hash::SHA1::DIGEST_SIZE, 0);

        hmac_hash::SHA1 ctx;
        ctx.init();
        ctx.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
        ctx.finish(digest);

        return std::vector<uint8_t>(digest, digest + hmac_hash::SHA1::DIGEST_SIZE);
    }

}

#endif // _HMAC_SHA1_HPP_INCLUDED
