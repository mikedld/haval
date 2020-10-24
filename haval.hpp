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

#include "haval.h"

#include <cassert>
#include <cinttypes>
#include <cstring>
#include <iostream>
#include <type_traits>

#define WORD_C UINT32_C

namespace haval
{

namespace detail
{

// constants for padding
constexpr std::uint8_t padding[128] = { //
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

word_t f_1(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return ((x1 & (x0 ^ x4)) ^ (x2 & x5) ^ (x3 & x6) ^ x0);
}

word_t f_2(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return ((x2 & ((x1 & ~x3) ^ (x4 & x5) ^ x6 ^ x0)) ^ (x4 & (x1 ^ x5)) ^ (x3 & x5) ^ x0);
}

word_t f_3(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return ((x3 & ((x1 & x2) ^ x6 ^ x0)) ^ (x1 & x4) ^ (x2 & x5) ^ x0);
}

word_t f_4(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return ((x4 & ((x5 & ~x2) ^ (x3 & ~x6) ^ x1 ^ x6 ^ x0)) ^ (x3 & ((x1 & x2) ^ x5 ^ x6)) ^ (x2 & x6) ^ x0);
}

word_t f_5(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return ((x0 & ((x1 & x2 & x3) ^ ~x5)) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6));
}

//
// Permutations phi_{i,j}, i=3,4,5, j=1,...,i.
//
// PASS = 3:
//               6 5 4 3 2 1 0
//               | | | | | | | (replaced by)
//  phi_{3,1}:   1 0 3 5 6 2 4
//  phi_{3,2}:   4 2 1 0 5 3 6
//  phi_{3,3}:   6 1 2 3 4 5 0
//
// PASS = 4:
//               6 5 4 3 2 1 0
//               | | | | | | | (replaced by)
//  phi_{4,1}:   2 6 1 4 5 3 0
//  phi_{4,2}:   3 5 2 0 1 6 4
//  phi_{4,3}:   1 4 3 6 0 2 5
//  phi_{4,4}:   6 4 0 5 2 1 3
//
// PASS = 5:
//               6 5 4 3 2 1 0
//               | | | | | | | (replaced by)
//  phi_{5,1}:   3 4 1 0 5 2 6
//  phi_{5,2}:   6 2 1 0 3 4 5
//  phi_{5,3}:   2 6 0 4 3 1 5
//  phi_{5,4}:   1 5 3 2 0 4 6
//  phi_{5,5}:   2 5 0 6 4 3 1
//

template<unsigned int pass_cnt>
word_t Fphi_1(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0) = delete;

template<>
word_t Fphi_1<3>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_1(x1, x0, x3, x5, x6, x2, x4);
}

template<>
word_t Fphi_1<4>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_1(x2, x6, x1, x4, x5, x3, x0);
}

template<>
word_t Fphi_1<5>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_1(x3, x4, x1, x0, x5, x2, x6);
}

template<unsigned int pass_cnt>
word_t Fphi_2(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0) = delete;

template<>
word_t Fphi_2<3>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_2(x4, x2, x1, x0, x5, x3, x6);
}

template<>
word_t Fphi_2<4>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_2(x3, x5, x2, x0, x1, x6, x4);
}

template<>
word_t Fphi_2<5>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_2(x6, x2, x1, x0, x3, x4, x5);
}

template<unsigned int pass_cnt>
word_t Fphi_3(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0) = delete;

template<>
word_t Fphi_3<3>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_3(x6, x1, x2, x3, x4, x5, x0);
}

template<>
word_t Fphi_3<4>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_3(x1, x4, x3, x6, x0, x2, x5);
}

template<>
word_t Fphi_3<5>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_3(x2, x6, x0, x4, x3, x1, x5);
}

template<unsigned int pass_cnt>
word_t Fphi_4(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0) = delete;

template<>
word_t Fphi_4<4>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_4(x6, x4, x0, x5, x2, x1, x3);
}

template<>
word_t Fphi_4<5>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_4(x1, x5, x3, x2, x0, x4, x6);
}

template<unsigned int pass_cnt>
word_t Fphi_5(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0) = delete;

template<>
word_t Fphi_5<5>(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0)
{
    return f_5(x2, x5, x0, x6, x4, x3, x1);
}

word_t rotate_right(word_t x, word_t n)
{
    return ((x >> n) | (x << (32 - n)));
}

template<unsigned int pass_cnt>
void FF_1(word_t& x7, word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0, word_t w)
{
    x7 = rotate_right(Fphi_1<pass_cnt>(x6, x5, x4, x3, x2, x1, x0), 7) + rotate_right(x7, 11) + w;
}

template<unsigned int pass_cnt>
void FF_2(word_t& x7, word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0, word_t w, word_t c)
{
    x7 = rotate_right(Fphi_2<pass_cnt>(x6, x5, x4, x3, x2, x1, x0), 7) + rotate_right(x7, 11) + w + c;
}

template<unsigned int pass_cnt>
void FF_3(word_t& x7, word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0, word_t w, word_t c)
{
    x7 = rotate_right(Fphi_3<pass_cnt>(x6, x5, x4, x3, x2, x1, x0), 7) + rotate_right(x7, 11) + w + c;
}

template<unsigned int pass_cnt>
void FF_4(word_t& x7, word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0, word_t w, word_t c)
{
    x7 = rotate_right(Fphi_4<pass_cnt>(x6, x5, x4, x3, x2, x1, x0), 7) + rotate_right(x7, 11) + w + c;
}

template<unsigned int pass_cnt>
void FF_5(word_t& x7, word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0, word_t w, word_t c)
{
    x7 = rotate_right(Fphi_5<pass_cnt>(x6, x5, x4, x3, x2, x1, x0), 7) + rotate_right(x7, 11) + w + c;
}

// translate every four characters into a word.
// assume the number of characters is a multiple of four.
void ch2uint(const std::uint8_t* string, word_t* word, std::size_t slen)
{
    const std::uint8_t* sp = string;
    word_t* wp = word;
    while (sp < string + slen) {
        *wp = word_t{sp[0]} | (word_t{sp[1]} << 8) | (word_t{sp[2]} << 16) | (word_t{sp[3]} << 24);
        wp++;
        sp += 4;
    }
}

// translate each word into four characters
void uint2ch(const word_t* word, std::uint8_t* string, std::size_t wlen)
{
    const word_t* wp = word;
    std::uint8_t* sp = string;
    while (wp < word + wlen) {
        sp[0] = static_cast<std::uint8_t>(*wp & 0xFF);
        sp[1] = static_cast<std::uint8_t>((*wp >> 8) & 0xFF);
        sp[2] = static_cast<std::uint8_t>((*wp >> 16) & 0xFF);
        sp[3] = static_cast<std::uint8_t>((*wp >> 24) & 0xFF);
        sp += 4;
        wp++;
    }
}

template<unsigned int pass_cnt, unsigned int curr_pass = pass_cnt>
void hash_block(
        word_t& t0,
        word_t& t1,
        word_t& t2,
        word_t& t3,
        word_t& t4,
        word_t& t5,
        word_t& t6,
        word_t& t7,
        const word_t* w,
        typename std::enable_if<curr_pass == 1, int>::type = 0)
{
    FF_1<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[0]);
    FF_1<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[1]);
    FF_1<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[2]);
    FF_1<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[3]);
    FF_1<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[4]);
    FF_1<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[5]);
    FF_1<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[6]);
    FF_1<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[7]);

    FF_1<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[8]);
    FF_1<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[9]);
    FF_1<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[10]);
    FF_1<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[11]);
    FF_1<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[12]);
    FF_1<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[13]);
    FF_1<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[14]);
    FF_1<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[15]);

    FF_1<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[16]);
    FF_1<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[17]);
    FF_1<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[18]);
    FF_1<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[19]);
    FF_1<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[20]);
    FF_1<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[21]);
    FF_1<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[22]);
    FF_1<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[23]);

    FF_1<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[24]);
    FF_1<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[25]);
    FF_1<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[26]);
    FF_1<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[27]);
    FF_1<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[28]);
    FF_1<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[29]);
    FF_1<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[30]);
    FF_1<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[31]);
}

template<unsigned int pass_cnt, unsigned int curr_pass = pass_cnt>
void hash_block(
        word_t& t0,
        word_t& t1,
        word_t& t2,
        word_t& t3,
        word_t& t4,
        word_t& t5,
        word_t& t6,
        word_t& t7,
        const word_t* w,
        typename std::enable_if<curr_pass == 2, int>::type = 0)
{
    hash_block<pass_cnt, curr_pass - 1>(t0, t1, t2, t3, t4, t5, t6, t7, w);

    FF_2<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[5], WORD_C(0x452821E6));
    FF_2<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[14], WORD_C(0x38D01377));
    FF_2<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[26], WORD_C(0xBE5466CF));
    FF_2<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[18], WORD_C(0x34E90C6C));
    FF_2<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[11], WORD_C(0xC0AC29B7));
    FF_2<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[28], WORD_C(0xC97C50DD));
    FF_2<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[7], WORD_C(0x3F84D5B5));
    FF_2<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[16], WORD_C(0xB5470917));

    FF_2<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[0], WORD_C(0x9216D5D9));
    FF_2<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[23], WORD_C(0x8979FB1B));
    FF_2<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[20], WORD_C(0xD1310BA6));
    FF_2<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[22], WORD_C(0x98DFB5AC));
    FF_2<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[1], WORD_C(0x2FFD72DB));
    FF_2<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[10], WORD_C(0xD01ADFB7));
    FF_2<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[4], WORD_C(0xB8E1AFED));
    FF_2<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[8], WORD_C(0x6A267E96));

    FF_2<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[30], WORD_C(0xBA7C9045));
    FF_2<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[3], WORD_C(0xF12C7F99));
    FF_2<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[21], WORD_C(0x24A19947));
    FF_2<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[9], WORD_C(0xB3916CF7));
    FF_2<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[17], WORD_C(0x0801F2E2));
    FF_2<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[24], WORD_C(0x858EFC16));
    FF_2<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[29], WORD_C(0x636920D8));
    FF_2<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[6], WORD_C(0x71574E69));

    FF_2<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[19], WORD_C(0xA458FEA3));
    FF_2<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[12], WORD_C(0xF4933D7E));
    FF_2<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[15], WORD_C(0x0D95748F));
    FF_2<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[13], WORD_C(0x728EB658));
    FF_2<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[2], WORD_C(0x718BCD58));
    FF_2<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[25], WORD_C(0x82154AEE));
    FF_2<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[31], WORD_C(0x7B54A41D));
    FF_2<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[27], WORD_C(0xC25A59B5));
}

template<unsigned int pass_cnt, unsigned int curr_pass = pass_cnt>
void hash_block(
        word_t& t0,
        word_t& t1,
        word_t& t2,
        word_t& t3,
        word_t& t4,
        word_t& t5,
        word_t& t6,
        word_t& t7,
        const word_t* w,
        typename std::enable_if<curr_pass == 3, int>::type = 0)
{
    hash_block<pass_cnt, curr_pass - 1>(t0, t1, t2, t3, t4, t5, t6, t7, w);

    FF_3<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[19], WORD_C(0x9C30D539));
    FF_3<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[9], WORD_C(0x2AF26013));
    FF_3<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[4], WORD_C(0xC5D1B023));
    FF_3<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[20], WORD_C(0x286085F0));
    FF_3<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[28], WORD_C(0xCA417918));
    FF_3<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[17], WORD_C(0xB8DB38EF));
    FF_3<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[8], WORD_C(0x8E79DCB0));
    FF_3<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[22], WORD_C(0x603A180E));

    FF_3<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[29], WORD_C(0x6C9E0E8B));
    FF_3<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[14], WORD_C(0xB01E8A3E));
    FF_3<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[25], WORD_C(0xD71577C1));
    FF_3<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[12], WORD_C(0xBD314B27));
    FF_3<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[24], WORD_C(0x78AF2FDA));
    FF_3<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[30], WORD_C(0x55605C60));
    FF_3<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[16], WORD_C(0xE65525F3));
    FF_3<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[26], WORD_C(0xAA55AB94));

    FF_3<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[31], WORD_C(0x57489862));
    FF_3<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[15], WORD_C(0x63E81440));
    FF_3<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[7], WORD_C(0x55CA396A));
    FF_3<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[3], WORD_C(0x2AAB10B6));
    FF_3<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[1], WORD_C(0xB4CC5C34));
    FF_3<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[0], WORD_C(0x1141E8CE));
    FF_3<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[18], WORD_C(0xA15486AF));
    FF_3<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[27], WORD_C(0x7C72E993));

    FF_3<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[13], WORD_C(0xB3EE1411));
    FF_3<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[6], WORD_C(0x636FBC2A));
    FF_3<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[21], WORD_C(0x2BA9C55D));
    FF_3<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[10], WORD_C(0x741831F6));
    FF_3<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[23], WORD_C(0xCE5C3E16));
    FF_3<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[11], WORD_C(0x9B87931E));
    FF_3<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[5], WORD_C(0xAFD6BA33));
    FF_3<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[2], WORD_C(0x6C24CF5C));
}

template<unsigned int pass_cnt, unsigned int curr_pass = pass_cnt>
void hash_block(
        word_t& t0,
        word_t& t1,
        word_t& t2,
        word_t& t3,
        word_t& t4,
        word_t& t5,
        word_t& t6,
        word_t& t7,
        const word_t* w,
        typename std::enable_if<curr_pass == 4, int>::type = 0)
{
    hash_block<pass_cnt, curr_pass - 1>(t0, t1, t2, t3, t4, t5, t6, t7, w);

    FF_4<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[24], WORD_C(0x7A325381));
    FF_4<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[4], WORD_C(0x28958677));
    FF_4<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[0], WORD_C(0x3B8F4898));
    FF_4<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[14], WORD_C(0x6B4BB9AF));
    FF_4<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[2], WORD_C(0xC4BFE81B));
    FF_4<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[7], WORD_C(0x66282193));
    FF_4<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[28], WORD_C(0x61D809CC));
    FF_4<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[23], WORD_C(0xFB21A991));

    FF_4<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[26], WORD_C(0x487CAC60));
    FF_4<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[6], WORD_C(0x5DEC8032));
    FF_4<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[30], WORD_C(0xEF845D5D));
    FF_4<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[20], WORD_C(0xE98575B1));
    FF_4<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[18], WORD_C(0xDC262302));
    FF_4<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[25], WORD_C(0xEB651B88));
    FF_4<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[19], WORD_C(0x23893E81));
    FF_4<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[3], WORD_C(0xD396ACC5));

    FF_4<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[22], WORD_C(0x0F6D6FF3));
    FF_4<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[11], WORD_C(0x83F44239));
    FF_4<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[31], WORD_C(0x2E0B4482));
    FF_4<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[21], WORD_C(0xA4842004));
    FF_4<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[8], WORD_C(0x69C8F04A));
    FF_4<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[27], WORD_C(0x9E1F9B5E));
    FF_4<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[12], WORD_C(0x21C66842));
    FF_4<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[9], WORD_C(0xF6E96C9A));

    FF_4<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[1], WORD_C(0x670C9C61));
    FF_4<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[29], WORD_C(0xABD388F0));
    FF_4<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[5], WORD_C(0x6A51A0D2));
    FF_4<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[15], WORD_C(0xD8542F68));
    FF_4<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[17], WORD_C(0x960FA728));
    FF_4<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[10], WORD_C(0xAB5133A3));
    FF_4<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[16], WORD_C(0x6EEF0B6C));
    FF_4<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[13], WORD_C(0x137A3BE4));
}

template<unsigned int pass_cnt, unsigned int curr_pass = pass_cnt>
void hash_block(
        word_t& t0,
        word_t& t1,
        word_t& t2,
        word_t& t3,
        word_t& t4,
        word_t& t5,
        word_t& t6,
        word_t& t7,
        const word_t* w,
        typename std::enable_if<curr_pass == 5, int>::type = 0)
{
    hash_block<pass_cnt, curr_pass - 1>(t0, t1, t2, t3, t4, t5, t6, t7, w);

    FF_5<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[27], WORD_C(0xBA3BF050));
    FF_5<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[3], WORD_C(0x7EFB2A98));
    FF_5<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[21], WORD_C(0xA1F1651D));
    FF_5<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[26], WORD_C(0x39AF0176));
    FF_5<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[17], WORD_C(0x66CA593E));
    FF_5<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[11], WORD_C(0x82430E88));
    FF_5<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[20], WORD_C(0x8CEE8619));
    FF_5<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[29], WORD_C(0x456F9FB4));

    FF_5<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[19], WORD_C(0x7D84A5C3));
    FF_5<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[0], WORD_C(0x3B8B5EBE));
    FF_5<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[12], WORD_C(0xE06F75D8));
    FF_5<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[7], WORD_C(0x85C12073));
    FF_5<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[13], WORD_C(0x401A449F));
    FF_5<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[8], WORD_C(0x56C16AA6));
    FF_5<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[31], WORD_C(0x4ED3AA62));
    FF_5<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[10], WORD_C(0x363F7706));

    FF_5<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[5], WORD_C(0x1BFEDF72));
    FF_5<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[9], WORD_C(0x429B023D));
    FF_5<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[14], WORD_C(0x37D0D724));
    FF_5<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[30], WORD_C(0xD00A1248));
    FF_5<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[18], WORD_C(0xDB0FEAD3));
    FF_5<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[6], WORD_C(0x49F1C09B));
    FF_5<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[28], WORD_C(0x075372C9));
    FF_5<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[24], WORD_C(0x80991B7B));

    FF_5<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, w[2], WORD_C(0x25D479D8));
    FF_5<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, w[23], WORD_C(0xF6E8DEF7));
    FF_5<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, w[16], WORD_C(0xE3FE501A));
    FF_5<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, w[22], WORD_C(0xB6794C3B));
    FF_5<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, w[4], WORD_C(0x976CE0BD));
    FF_5<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, w[1], WORD_C(0x04C006BA));
    FF_5<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, w[25], WORD_C(0xC1A94FB6));
    FF_5<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, w[15], WORD_C(0x409F60C4));
}

// tailor the last output
template<unsigned int fpt_len>
void tailor(haval_context& context) = delete;

template<>
void tailor<128>(haval_context& context)
{
    auto& f = context.fingerprint;

    f[0] += rotate_right(
            (f[7] & WORD_C(0x000000FF)) | (f[6] & WORD_C(0xFF000000)) | (f[5] & WORD_C(0x00FF0000)) |
                    (f[4] & WORD_C(0x0000FF00)),
            8);
    f[1] += rotate_right(
            (f[7] & WORD_C(0x0000FF00)) | (f[6] & WORD_C(0x000000FF)) | (f[5] & WORD_C(0xFF000000)) |
                    (f[4] & WORD_C(0x00FF0000)),
            16);
    f[2] += rotate_right(
            (f[7] & WORD_C(0x00FF0000)) | (f[6] & WORD_C(0x0000FF00)) | (f[5] & WORD_C(0x000000FF)) |
                    (f[4] & WORD_C(0xFF000000)),
            24);
    f[3] += (f[7] & WORD_C(0xFF000000)) | (f[6] & WORD_C(0x00FF0000)) | (f[5] & WORD_C(0x0000FF00)) |
            (f[4] & WORD_C(0x000000FF));
}

template<>
void tailor<160>(haval_context& context)
{
    auto& f = context.fingerprint;

    f[0] += rotate_right((f[7] & WORD_C(0x3F)) | (f[6] & (WORD_C(0x7F) << 25)) | (f[5] & (WORD_C(0x3F) << 19)), 19);
    f[1] += rotate_right((f[7] & (WORD_C(0x3F) << 6)) | (f[6] & WORD_C(0x3F)) | (f[5] & (WORD_C(0x7F) << 25)), 25);
    f[2] += (f[7] & (WORD_C(0x7F) << 12)) | (f[6] & (WORD_C(0x3F) << 6)) | (f[5] & WORD_C(0x3F));
    f[3] += ((f[7] & (WORD_C(0x3F) << 19)) | (f[6] & (WORD_C(0x7F) << 12)) | (f[5] & (WORD_C(0x3F) << 6))) >> 6;
    f[4] += ((f[7] & (WORD_C(0x7F) << 25)) | (f[6] & (WORD_C(0x3F) << 19)) | (f[5] & (WORD_C(0x7F) << 12))) >> 12;
}

template<>
void tailor<192>(haval_context& context)
{
    auto& f = context.fingerprint;

    f[0] += rotate_right((f[7] & WORD_C(0x1F)) | (f[6] & (WORD_C(0x3F) << 26)), 26);
    f[1] += (f[7] & (WORD_C(0x1F) << 5)) | (f[6] & WORD_C(0x1F));
    f[2] += ((f[7] & (WORD_C(0x3F) << 10)) | (f[6] & (WORD_C(0x1F) << 5))) >> 5;
    f[3] += ((f[7] & (WORD_C(0x1F) << 16)) | (f[6] & (WORD_C(0x3F) << 10))) >> 10;
    f[4] += ((f[7] & (WORD_C(0x1F) << 21)) | (f[6] & (WORD_C(0x1F) << 16))) >> 16;
    f[5] += ((f[7] & (WORD_C(0x3F) << 26)) | (f[6] & (WORD_C(0x1F) << 21))) >> 21;
}

template<>
void tailor<224>(haval_context& context)
{
    auto& f = context.fingerprint;

    f[0] += (f[7] >> 27) & 0x1F;
    f[1] += (f[7] >> 22) & 0x1F;
    f[2] += (f[7] >> 18) & 0x0F;
    f[3] += (f[7] >> 13) & 0x1F;
    f[4] += (f[7] >> 9) & 0x0F;
    f[5] += (f[7] >> 4) & 0x1F;
    f[6] += f[7] & 0x0F;
}

template<>
void tailor<256>(haval_context& /*context*/)
{
}

} // namespace detail

// initialization
template<unsigned int pass_cnt, unsigned int fpt_len>
void haval<pass_cnt, fpt_len>::start()
{
    // clear count
    m_context.count[0] = 0;
    m_context.count[1] = 0;
    // initial fingerprint
    m_context.fingerprint[0] = WORD_C(0x243F6A88);
    m_context.fingerprint[1] = WORD_C(0x85A308D3);
    m_context.fingerprint[2] = WORD_C(0x13198A2E);
    m_context.fingerprint[3] = WORD_C(0x03707344);
    m_context.fingerprint[4] = WORD_C(0xA4093822);
    m_context.fingerprint[5] = WORD_C(0x299F31D0);
    m_context.fingerprint[6] = WORD_C(0x082EFA98);
    m_context.fingerprint[7] = WORD_C(0xEC4E6C89);
}

// hash a string of specified length.
// to be used in conjunction with haval_start and haval_end.
template<unsigned int pass_cnt, unsigned int fpt_len>
void haval<pass_cnt, fpt_len>::update(const void* vdata, std::size_t data_len)
{
    assert(data_len <= UINT32_MAX);

    const std::uint8_t* data = static_cast<const std::uint8_t*>(vdata);

    // calculate the number of bytes in the remainder
    std::size_t rmd_len = (m_context.count[0] >> 3) & 0x7F;
    std::size_t fill_len = 128 - rmd_len;

    // update the number of bits
    m_context.count[0] += static_cast<detail::word_t>(data_len) << 3;
    if (m_context.count[0] < (data_len << 3)) {
        m_context.count[1]++;
    }
    m_context.count[1] += static_cast<detail::word_t>(data_len) >> 29;

    std::size_t i = 0;

#ifdef HAVAL_LITTLE_ENDIAN

    // hash as many blocks as possible
    if (rmd_len + data_len >= 128) {
        std::memcpy(reinterpret_cast<std::uint8_t*>(m_context.block) + rmd_len, data, fill_len);
        hash_block();
        for (i = fill_len; i + 127 < data_len; i += 128) {
            std::memcpy(m_context.block, data + i, 128);
            hash_block();
        }
        rmd_len = 0;
    }
    std::memcpy(reinterpret_cast<std::uint8_t*>(m_context.block) + rmd_len, data + i, data_len - i);

#else

    // hash as many blocks as possible
    if (rmd_len + data_len >= 128) {
        std::memcpy(&m_context.remainder[rmd_len], data, fill_len);
        detail::ch2uint(m_context.remainder, m_context.block, 128);
        hash_block();
        for (i = fill_len; i + 127 < data_len; i += 128) {
            std::memcpy(m_context.remainder, data + i, 128);
            detail::ch2uint(m_context.remainder, m_context.block, 128);
            hash_block();
        }
        rmd_len = 0;
    }
    // save the remaining input chars
    std::memcpy(&m_context.remainder[rmd_len], data + i, data_len - i);

#endif
}

// finalization
template<unsigned int pass_cnt, unsigned int fpt_len>
std::string haval<pass_cnt, fpt_len>::end()
{
    // save the version number, the number of passes, the fingerprint
    // length and the number of bits in the unpadded message.
    std::uint8_t tail[10];
    tail[0] = static_cast<std::uint8_t>(((fpt_len & 0x3) << 6) | ((pass_cnt & 0x7) << 3) | (detail::version & 0x7));
    tail[1] = static_cast<std::uint8_t>((fpt_len >> 2) & 0xFF);
    detail::uint2ch(m_context.count, &tail[2], 2);

    // pad out to 118 mod 128
    std::size_t rmd_len = (m_context.count[0] >> 3) & 0x7f;
    std::size_t pad_len = (rmd_len < 118) ? (118 - rmd_len) : (246 - rmd_len);
    update(detail::padding, pad_len);

    // append the version number, the number of passes,
    // the fingerprint length and the number of bits
    update(tail, 10);

    // tailor the last output
    detail::tailor<fpt_len>(m_context);

    // translate and save the final fingerprint
    std::string final_fpt(fpt_len >> 3, '\0');
    detail::uint2ch(m_context.fingerprint, reinterpret_cast<std::uint8_t*>(&final_fpt[0]), fpt_len >> 5);

    // clear the state information
    std::memset(&m_context, 0, sizeof(m_context));

    return final_fpt;
}

// hash a 32-word block
template<unsigned int pass_cnt, unsigned int fpt_len>
void haval<pass_cnt, fpt_len>::hash_block()
{
    // make use of internal registers
    auto t0 = m_context.fingerprint[0];
    auto t1 = m_context.fingerprint[1];
    auto t2 = m_context.fingerprint[2];
    auto t3 = m_context.fingerprint[3];
    auto t4 = m_context.fingerprint[4];
    auto t5 = m_context.fingerprint[5];
    auto t6 = m_context.fingerprint[6];
    auto t7 = m_context.fingerprint[7];

    detail::hash_block<pass_cnt>(t0, t1, t2, t3, t4, t5, t6, t7, m_context.block);

    m_context.fingerprint[0] += t0;
    m_context.fingerprint[1] += t1;
    m_context.fingerprint[2] += t2;
    m_context.fingerprint[3] += t3;
    m_context.fingerprint[4] += t4;
    m_context.fingerprint[5] += t5;
    m_context.fingerprint[6] += t6;
    m_context.fingerprint[7] += t7;
}

// hash a block
template<unsigned int pass_cnt, unsigned int fpt_len>
std::string haval<pass_cnt, fpt_len>::from_data(const void* data, std::size_t data_len)
{
    haval<pass_cnt, fpt_len> context;
    context.start();
    context.update(data, data_len);
    return context.end();
}

// hash a string
template<unsigned int pass_cnt, unsigned int fpt_len>
std::string haval<pass_cnt, fpt_len>::from_string(const std::string& data)
{
    return from_data(data.data(), data.size());
}

// hash a stream
template<unsigned int pass_cnt, unsigned int fpt_len>
std::string haval<pass_cnt, fpt_len>::from_stream(std::istream& stream)
{
    haval<pass_cnt, fpt_len> context;
    context.start();

    char buffer[1024];

    for (;;) {
        stream.read(buffer, sizeof(buffer));
        context.update(buffer, static_cast<std::size_t>(stream.gcount()));
        if (stream.eof()) {
            break;
        }
    }

    return context.end();
}

} // namespace haval

#undef WORD_C
