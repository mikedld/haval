// haval.h:  specifies the interface to the HAVAL (V.1) hashing library.
//
// Copyright (c) 2003 Calyptix Security Corporation
// Copyright (c) 2020 Mike Gelfand
// All rights reserved.
//
// This code is derived from software contributed to Calyptix Security
// Corporation by Yuliang Zheng.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above
//    copyright notice, this list of conditions and the following
//    disclaimer in the documentation and/or other materials provided
//    with the distribution.
// 3. Neither the name of Calyptix Security Corporation nor the
//    names of its contributors may be used to endorse or promote
//    products derived from this software without specific prior
//    written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// -------------------------------------------------------------------
//
//     HAVAL is a one-way hashing algorithm with the following
//     collision-resistant property:
//            It is computationally infeasible to find two or more
//            messages that are hashed into the same fingerprint.
//
// Reference:
//      Y. Zheng, J. Pieprzyk and J. Seberry:
//      ``HAVAL --- a one-way hashing algorithm with variable
//      length of output'', Advances in Cryptology --- AUSCRYPT'92,
//      Lecture Notes in Computer Science,  Vol.718, pp.83-104,
//      Springer-Verlag, 1993.
//
//     This library provides routines to hash
//       -  a string,
//       -  a file,
//       -  input from the standard input device,
//       -  a 32-word block, and
//       -  a string of specified length.
//
// Authors:    Yuliang Zheng and Lawrence Teo
//             Calyptix Security Corporation
//             P.O. Box 561508, Charlotte, NC 28213, USA
//             Email: info@calyptix.com
//             URL:   http://www.calyptix.com/
//             Voice: +1 704 806 8635
//
// For a list of changes, see the ChangeLog file.

#pragma once

#include <string>
#include <iosfwd>

namespace haval
{

namespace detail
{

// a HAVAL word = 32 bits
using word_t = unsigned int;

// current version number
constexpr word_t version = 1;

struct haval_context {
    // number of bits in a message
    word_t count[2];
    // current state of fingerprint
    word_t fingerprint[8];
    // buffer for a 32-word block
    word_t block[32];
    // unhashed chars (No.<128)
    unsigned char remainder[32 * 4];
};

} // namespace detail

template<unsigned int pass_cnt, unsigned int fpt_len>
class haval
{
    static_assert(pass_cnt >= 3, "");
    static_assert(pass_cnt <= 5, "");

    static_assert(fpt_len >= 128, "");
    static_assert(fpt_len <= 256, "");
    static_assert(fpt_len % 32 == 0, "");

public:
    // initialization
    void start();
    // updating routine
    void update(const void* data, std::size_t data_len);
    // finalization
    std::string end();

    // hash a block
    static std::string from_data(const void* data, std::size_t data_len);
    // hash a string
    static std::string from_string(const std::string& data);
    // hash a stream
    static std::string from_stream(std::istream& stream);

private:
    void hash_block();

private:
    detail::haval_context m_context;
};

} // namespace haval
