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

/* Based on: http://www.zedwood.com/article/cpp-sha512-function
 * Modified by Elektro Yar, 2020-06-18
 */

#ifndef _HMAC_SHA512_HPP_INCLUDED
#define _HMAC_SHA512_HPP_INCLUDED

#include <string>

namespace hmac_hash {

	/// \brief SHA512 hashing class
    ///
    /// SHA-512 is the largest hash function in the SHA-2 family.
    /// It provides 256-bit security for digital signatures and hash-only applications.
    class SHA512 {
    protected:
        const static uint64_t sha512_k[];

    public:

        /// \brief Initializes the SHA512 context
        void init();

        /// \brief Updates the SHA512 context with message data
        /// \param message Pointer to the input data
        /// \param length Length of the input data in bytes
        void update(const uint8_t *message, const size_t length);

        /// \brief Finalizes the SHA512 computation
        /// \param digest Output buffer of size DIGEST_SIZE
        void final(uint8_t *digest);

        static const size_t DIGEST_SIZE = ( 512 / 8);         ///< Hash output size in bytes
        static const size_t SHA384_512_BLOCK_SIZE = (1024/8); ///< Block size in bytes

    protected:
        void transform(const uint8_t *message, const size_t block_nb);
        size_t m_tot_len;
        size_t m_len;
        uint8_t m_block[2 * SHA384_512_BLOCK_SIZE];
        uint64_t m_h[8];
    };

    /// \brief Computes SHA512 hash for the given string
    /// \param input Input string
    /// \return Binary hash result as a std::string
    std::string sha512(const std::string &input);
}

#endif // _HMAC_SHA512_HPP_INCLUDED
