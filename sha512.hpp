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

#ifndef SHA512_HPP_INCLUDED
#define SHA512_HPP_INCLUDED

#include <string>

namespace hmac_hash {

    /** \brief Класс для расчета SHA512
     * SHA-512 является самой большой хеш-функцией в семействе хеш-функций SHA-2.
     * SHA-512 обеспечивает 256 бит безопасности для цифровых подписей
     * и приложений только для хэширования.
     */
    class SHA512 {
    protected:
        const static uint64_t sha512_k[];

    public:

        /** \brief Инициализировать SHA512
         */
        void init();

        /** \brief Обновить SHA512
         * \param message Новое сообщение, которое добавляем для расчета SHA512
         * \param length Длина сообщения
         */
        void update(const uint8_t *message, const size_t length);

        /** \brief Результат SHA512
         * \param digest Результат расчета SHA512, занимает DIGEST_SIZE байт.
         */
        void final(uint8_t *digest);

        static const size_t DIGEST_SIZE = ( 512 / 8);
        static const size_t SHA384_512_BLOCK_SIZE = (1024/8);

    protected:
        void transform(const uint8_t *message, const size_t block_nb);
        size_t m_tot_len;
        size_t m_len;
        uint8_t m_block[2 * SHA384_512_BLOCK_SIZE];
        uint64_t m_h[8];
    };

    /** \brief Посчитать SHA512 для строки
     * \param input Строка, для которой счтаем хеш
     * \return Хеш в виде строки
     */
    std::string sha512(const std::string &input);
}

#endif // SHA512_HPP_INCLUDED
