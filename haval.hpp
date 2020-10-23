// haval.hpp:  specifies the routines in the HAVAL (V.1) hashing library.
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
// Descriptions:
//     -  haval_string:      hash a string
//     -  haval_file:        hash a file
//     -  haval_stdin:       filter -- hash input from the stdin device
//     -  haval_hash:        hash a string of specified length
//                           (Haval_hash is used in conjunction with
//                            haval_start & haval_end.)
//     -  haval_hash_block:  hash a 32-word block
//     -  haval_start:       initialization
//     -  haval_end:         finalization
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

#include "haval.h"

#include <cstring>
#include <type_traits>
#include <iostream>

namespace haval
{

namespace detail
{

// constants for padding
const unsigned char padding[128] = { //
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

template<typename T>
word_t to_word(T x)
{
    return static_cast<word_t>(x);
}

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
word_t Fphi_1(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0);

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
word_t Fphi_2(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0);

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
word_t Fphi_3(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0);

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
word_t Fphi_4(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0);

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
word_t Fphi_5(word_t x6, word_t x5, word_t x4, word_t x3, word_t x2, word_t x1, word_t x0);

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
void ch2uint(unsigned char* string, word_t* word, std::size_t slen)
{
    unsigned char* sp = string;
    word_t* wp = word;
    while (sp < string + slen) {
        *wp++ = to_word(*sp) | (to_word(*(sp + 1)) << 8) | (to_word(*(sp + 2)) << 16) | (to_word(*(sp + 3)) << 24);
        sp += 4;
    }
}

// translate each word into four characters
void uint2ch(word_t* word, unsigned char* string, std::size_t wlen)
{
    word_t* wp = word;
    unsigned char* sp = string;
    while (wp < word + wlen) {
        *(sp++) = static_cast<unsigned char>(*wp & 0xFF);
        *(sp++) = static_cast<unsigned char>((*wp >> 8) & 0xFF);
        *(sp++) = static_cast<unsigned char>((*wp >> 16) & 0xFF);
        *(sp++) = static_cast<unsigned char>((*wp >> 24) & 0xFF);
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
    FF_1<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w));
    FF_1<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 1));
    FF_1<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 2));
    FF_1<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 3));
    FF_1<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 4));
    FF_1<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 5));
    FF_1<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 6));
    FF_1<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 7));

    FF_1<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 8));
    FF_1<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9));
    FF_1<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 10));
    FF_1<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 11));
    FF_1<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 12));
    FF_1<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 13));
    FF_1<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 14));
    FF_1<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 15));

    FF_1<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 16));
    FF_1<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 17));
    FF_1<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 18));
    FF_1<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 19));
    FF_1<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 20));
    FF_1<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 21));
    FF_1<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 22));
    FF_1<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 23));

    FF_1<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 24));
    FF_1<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 25));
    FF_1<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 26));
    FF_1<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 27));
    FF_1<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 28));
    FF_1<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 29));
    FF_1<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 30));
    FF_1<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 31));
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

    FF_2<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 5), 0x452821E6L);
    FF_2<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 14), 0x38D01377L);
    FF_2<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 26), 0xBE5466CFL);
    FF_2<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 18), 0x34E90C6CL);
    FF_2<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 11), 0xC0AC29B7L);
    FF_2<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 28), 0xC97C50DDL);
    FF_2<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 7), 0x3F84D5B5L);
    FF_2<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 16), 0xB5470917L);

    FF_2<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w), 0x9216D5D9L);
    FF_2<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 23), 0x8979FB1BL);
    FF_2<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 20), 0xD1310BA6L);
    FF_2<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 22), 0x98DFB5ACL);
    FF_2<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 1), 0x2FFD72DBL);
    FF_2<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 10), 0xD01ADFB7L);
    FF_2<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 4), 0xB8E1AFEDL);
    FF_2<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 8), 0x6A267E96L);

    FF_2<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 30), 0xBA7C9045L);
    FF_2<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 3), 0xF12C7F99L);
    FF_2<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0x24A19947L);
    FF_2<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 9), 0xB3916CF7L);
    FF_2<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 17), 0x0801F2E2L);
    FF_2<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 24), 0x858EFC16L);
    FF_2<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 29), 0x636920D8L);
    FF_2<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 6), 0x71574E69L);

    FF_2<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0xA458FEA3L);
    FF_2<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 12), 0xF4933D7EL);
    FF_2<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 15), 0x0D95748FL);
    FF_2<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 13), 0x728EB658L);
    FF_2<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 2), 0x718BCD58L);
    FF_2<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 25), 0x82154AEEL);
    FF_2<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 31), 0x7B54A41DL);
    FF_2<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 27), 0xC25A59B5L);
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

    FF_3<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0x9C30D539L);
    FF_3<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9), 0x2AF26013L);
    FF_3<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 4), 0xC5D1B023L);
    FF_3<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 20), 0x286085F0L);
    FF_3<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 28), 0xCA417918L);
    FF_3<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 17), 0xB8DB38EFL);
    FF_3<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 8), 0x8E79DCB0L);
    FF_3<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 22), 0x603A180EL);

    FF_3<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 29), 0x6C9E0E8BL);
    FF_3<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 14), 0xB01E8A3EL);
    FF_3<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 25), 0xD71577C1L);
    FF_3<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 12), 0xBD314B27L);
    FF_3<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 24), 0x78AF2FDAL);
    FF_3<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 30), 0x55605C60L);
    FF_3<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 16), 0xE65525F3L);
    FF_3<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 26), 0xAA55AB94L);

    FF_3<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 31), 0x57489862L);
    FF_3<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 15), 0x63E81440L);
    FF_3<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 7), 0x55CA396AL);
    FF_3<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 3), 0x2AAB10B6L);
    FF_3<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 1), 0xB4CC5C34L);
    FF_3<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w), 0x1141E8CEL);
    FF_3<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 18), 0xA15486AFL);
    FF_3<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 27), 0x7C72E993L);

    FF_3<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 13), 0xB3EE1411L);
    FF_3<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 6), 0x636FBC2AL);
    FF_3<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0x2BA9C55DL);
    FF_3<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 10), 0x741831F6L);
    FF_3<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 23), 0xCE5C3E16L);
    FF_3<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 11), 0x9B87931EL);
    FF_3<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 5), 0xAFD6BA33L);
    FF_3<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 2), 0x6C24CF5CL);
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

    FF_4<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 24), 0x7A325381L);
    FF_4<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 4), 0x28958677L);
    FF_4<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w), 0x3B8F4898L);
    FF_4<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 14), 0x6B4BB9AFL);
    FF_4<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 2), 0xC4BFE81BL);
    FF_4<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 7), 0x66282193L);
    FF_4<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 28), 0x61D809CCL);
    FF_4<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 23), 0xFB21A991L);

    FF_4<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 26), 0x487CAC60L);
    FF_4<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 6), 0x5DEC8032L);
    FF_4<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 30), 0xEF845D5DL);
    FF_4<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 20), 0xE98575B1L);
    FF_4<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 18), 0xDC262302L);
    FF_4<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 25), 0xEB651B88L);
    FF_4<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 19), 0x23893E81L);
    FF_4<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 3), 0xD396ACC5L);

    FF_4<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 22), 0x0F6D6FF3L);
    FF_4<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 11), 0x83F44239L);
    FF_4<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 31), 0x2E0B4482L);
    FF_4<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 21), 0xA4842004L);
    FF_4<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 8), 0x69C8F04AL);
    FF_4<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 27), 0x9E1F9B5EL);
    FF_4<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 12), 0x21C66842L);
    FF_4<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 9), 0xF6E96C9AL);

    FF_4<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 1), 0x670C9C61L);
    FF_4<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 29), 0xABD388F0L);
    FF_4<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 5), 0x6A51A0D2L);
    FF_4<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 15), 0xD8542F68L);
    FF_4<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 17), 0x960FA728L);
    FF_4<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 10), 0xAB5133A3L);
    FF_4<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 16), 0x6EEF0B6CL);
    FF_4<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 13), 0x137A3BE4L);
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

    FF_5<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 27), 0xBA3BF050L);
    FF_5<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 3), 0x7EFB2A98L);
    FF_5<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 21), 0xA1F1651DL);
    FF_5<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 26), 0x39AF0176L);
    FF_5<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 17), 0x66CA593EL);
    FF_5<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 11), 0x82430E88L);
    FF_5<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 20), 0x8CEE8619L);
    FF_5<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 29), 0x456F9FB4L);

    FF_5<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 19), 0x7D84A5C3L);
    FF_5<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w), 0x3B8B5EBEL);
    FF_5<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 12), 0xE06F75D8L);
    FF_5<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 7), 0x85C12073L);
    FF_5<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 13), 0x401A449FL);
    FF_5<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 8), 0x56C16AA6L);
    FF_5<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 31), 0x4ED3AA62L);
    FF_5<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 10), 0x363F7706L);

    FF_5<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 5), 0x1BFEDF72L);
    FF_5<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 9), 0x429B023DL);
    FF_5<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 14), 0x37D0D724L);
    FF_5<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 30), 0xD00A1248L);
    FF_5<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 18), 0xDB0FEAD3L);
    FF_5<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 6), 0x49F1C09BL);
    FF_5<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 28), 0x075372C9L);
    FF_5<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 24), 0x80991B7BL);

    FF_5<pass_cnt>(t7, t6, t5, t4, t3, t2, t1, t0, *(w + 2), 0x25D479D8L);
    FF_5<pass_cnt>(t6, t5, t4, t3, t2, t1, t0, t7, *(w + 23), 0xF6E8DEF7L);
    FF_5<pass_cnt>(t5, t4, t3, t2, t1, t0, t7, t6, *(w + 16), 0xE3FE501AL);
    FF_5<pass_cnt>(t4, t3, t2, t1, t0, t7, t6, t5, *(w + 22), 0xB6794C3BL);
    FF_5<pass_cnt>(t3, t2, t1, t0, t7, t6, t5, t4, *(w + 4), 0x976CE0BDL);
    FF_5<pass_cnt>(t2, t1, t0, t7, t6, t5, t4, t3, *(w + 1), 0x04C006BAL);
    FF_5<pass_cnt>(t1, t0, t7, t6, t5, t4, t3, t2, *(w + 25), 0xC1A94FB6L);
    FF_5<pass_cnt>(t0, t7, t6, t5, t4, t3, t2, t1, *(w + 15), 0x409F60C4L);
}

// tailor the last output
template<unsigned int fpt_len>
void tailor(haval_context& context);

template<>
void tailor<128>(haval_context& context)
{
    auto& f = context.fingerprint;

    f[0] += rotate_right((f[7] & 0x000000FFL) | (f[6] & 0xFF000000L) | (f[5] & 0x00FF0000L) | (f[4] & 0x0000FF00L), 8);
    f[1] += rotate_right((f[7] & 0x0000FF00L) | (f[6] & 0x000000FFL) | (f[5] & 0xFF000000L) | (f[4] & 0x00FF0000L), 16);
    f[2] += rotate_right((f[7] & 0x00FF0000L) | (f[6] & 0x0000FF00L) | (f[5] & 0x000000FFL) | (f[4] & 0xFF000000L), 24);
    f[3] += (f[7] & 0xFF000000L) | (f[6] & 0x00FF0000L) | (f[5] & 0x0000FF00L) | (f[4] & 0x000000FFL);
}

template<>
void tailor<160>(haval_context& context)
{
    auto& f = context.fingerprint;

    f[0] += rotate_right((f[7] & to_word(0x3F)) | (f[6] & (to_word(0x7F) << 25)) | (f[5] & (to_word(0x3F) << 19)), 19);
    f[1] += rotate_right((f[7] & (to_word(0x3F) << 6)) | (f[6] & to_word(0x3F)) | (f[5] & (to_word(0x7F) << 25)), 25);
    f[2] += (f[7] & (to_word(0x7F) << 12)) | (f[6] & (to_word(0x3F) << 6)) | (f[5] & to_word(0x3F));
    f[3] += ((f[7] & (to_word(0x3F) << 19)) | (f[6] & (to_word(0x7F) << 12)) | (f[5] & (to_word(0x3F) << 6))) >> 6;
    f[4] += ((f[7] & (to_word(0x7F) << 25)) | (f[6] & (to_word(0x3F) << 19)) | (f[5] & (to_word(0x7F) << 12))) >> 12;
}

template<>
void tailor<192>(haval_context& context)
{
    auto& f = context.fingerprint;

    f[0] += rotate_right((f[7] & to_word(0x1F)) | (f[6] & (to_word(0x3F) << 26)), 26);
    f[1] += (f[7] & (to_word(0x1F) << 5)) | (f[6] & to_word(0x1F));
    f[2] += ((f[7] & (to_word(0x3F) << 10)) | (f[6] & (to_word(0x1F) << 5))) >> 5;
    f[3] += ((f[7] & (to_word(0x1F) << 16)) | (f[6] & (to_word(0x3F) << 10))) >> 10;
    f[4] += ((f[7] & (to_word(0x1F) << 21)) | (f[6] & (to_word(0x1F) << 16))) >> 16;
    f[5] += ((f[7] & (to_word(0x3F) << 26)) | (f[6] & (to_word(0x1F) << 21))) >> 21;
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
    m_context.fingerprint[0] = 0x243F6A88L;
    m_context.fingerprint[1] = 0x85A308D3L;
    m_context.fingerprint[2] = 0x13198A2EL;
    m_context.fingerprint[3] = 0x03707344L;
    m_context.fingerprint[4] = 0xA4093822L;
    m_context.fingerprint[5] = 0x299F31D0L;
    m_context.fingerprint[6] = 0x082EFA98L;
    m_context.fingerprint[7] = 0xEC4E6C89L;
}

// hash a string of specified length.
// to be used in conjunction with haval_start and haval_end.
template<unsigned int pass_cnt, unsigned int fpt_len>
void haval<pass_cnt, fpt_len>::update(const void* vdata, std::size_t data_len)
{
    std::size_t i, rmd_len, fill_len;
    const unsigned char* data = static_cast<const unsigned char*>(vdata);

    // calculate the number of bytes in the remainder
    rmd_len = (m_context.count[0] >> 3) & 0x7F;
    fill_len = 128 - rmd_len;

    // update the number of bits
    m_context.count[0] += detail::to_word(data_len) << 3;
    if (m_context.count[0] < (data_len << 3)) {
        m_context.count[1]++;
    }
    m_context.count[1] += detail::to_word(data_len) >> 29;

#ifdef HAVAL_LITTLE_ENDIAN

    // hash as many blocks as possible
    if (rmd_len + data_len >= 128) {
        std::memcpy(reinterpret_cast<unsigned char*>(m_context.block) + rmd_len, data, fill_len);
        hash_block();
        for (i = fill_len; i + 127 < data_len; i += 128) {
            std::memcpy(m_context.block, data + i, 128);
            hash_block();
        }
        rmd_len = 0;
    } else {
        i = 0;
    }
    std::memcpy(reinterpret_cast<unsigned char*>(m_context.block) + rmd_len, data + i, data_len - i);

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
    } else {
        i = 0;
    }
    // save the remaining input chars
    std::memcpy(&m_context.remainder[rmd_len], data + i, data_len - i);

#endif
}

// finalization
template<unsigned int pass_cnt, unsigned int fpt_len>
std::string haval<pass_cnt, fpt_len>::end()
{
    std::string final_fpt;
    unsigned char tail[10];
    std::size_t rmd_len, pad_len;

    // save the version number, the number of passes, the fingerprint
    // length and the number of bits in the unpadded message.
    tail[0] = static_cast<unsigned char>(((fpt_len & 0x3) << 6) | ((pass_cnt & 0x7) << 3) | (detail::version & 0x7));
    tail[1] = static_cast<unsigned char>((fpt_len >> 2) & 0xFF);
    detail::uint2ch(m_context.count, &tail[2], 2);

    // pad out to 118 mod 128
    rmd_len = (m_context.count[0] >> 3) & 0x7f;
    pad_len = (rmd_len < 118) ? (118 - rmd_len) : (246 - rmd_len);
    update(detail::padding, pad_len);

    // append the version number, the number of passes,
    // the fingerprint length and the number of bits
    update(tail, 10);

    // tailor the last output
    detail::tailor<fpt_len>(m_context);

    // translate and save the final fingerprint
    final_fpt.resize(fpt_len >> 3);
    detail::uint2ch(m_context.fingerprint, reinterpret_cast<unsigned char*>(&final_fpt[0]), fpt_len >> 5);

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
    const auto* w = m_context.block;

    detail::hash_block<pass_cnt>(t0, t1, t2, t3, t4, t5, t6, t7, w);

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
