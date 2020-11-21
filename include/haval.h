// Copyright (c) 2020, Mike Gelfand
// Copyright (c) 2003, Calyptix Security Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>

namespace haval
{

namespace detail
{

// a HAVAL word = 32 bits
using word_t = std::uint32_t;

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
    std::uint8_t remainder[32 * 4];
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
    using size_type = std::size_t;

    static constexpr size_type result_size = fpt_len >> 3;

public:
    // initialization
    void start();
    // updating routine
    void update(const void* data, size_type data_len);
    // finalization
    void end_to(void* data);
    std::string end();

    // hash a block
    static std::string hash(const void* data, size_type data_len);
    // hash a string
    static std::string hash(const std::string& data);
    // hash a stream
    static std::string hash(std::istream& stream);

private:
    void hash_block();

private:
    detail::haval_context m_context;
};

} // namespace haval
