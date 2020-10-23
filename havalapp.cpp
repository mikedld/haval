// havaltest.cpp:  specifies a test program for the HAVAL hashing library.
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
// Arguments for the test program:
//
//     (none)    - hash input from stdin
//     ?,-?,-h   - show help menu
//     -e        - test whether your machine is little-endian
//     -mstring  - hash message (string of chars)
//     -s        - test speed
//     file_name - hash file
//
// Authors:    Yuliang Zheng and Lawrence Teo
//             Calyptix Security Corporation
//             P.O. Box 561508, Charlotte, NC 28213, USA
//             Email: info@calyptix.com
//             URL:   http://www.calyptix.com/
//             Voice: +1 704 806 8635
//
// For a list of changes, see the ChangeLog file.

#include "haval.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include <time.h>

// number of test blocks
// #define NUMBER_OF_BLOCKS 5000
// number of bytes in a block
// #define BLOCK_SIZE 5000

namespace
{

unsigned int get_env_uint(const char* key, unsigned int default_value)
{
    const char* str_value = std::getenv(key);
    int int_value = str_value != nullptr ? std::atoi(str_value) : 0;
    return int_value > 0 ? static_cast<unsigned int>(int_value) : default_value;
}

// test the speed of HAVAL
template<unsigned int pass_cnt, unsigned int fpt_len>
void haval_speed()
{
    unsigned int blocks_cnt = get_env_uint("HAVAL_NUMBER_OF_BLOCKS", 5000);
    unsigned int block_size = get_env_uint("HAVAL_BLOCK_SIZE", 5000);

    haval::haval<pass_cnt, fpt_len> hasher;
    std::unique_ptr<unsigned char[]> buff(new unsigned char[block_size]);
    std::string fingerprint;
    clock_t clks;
    double cpu_time;
    unsigned int i;

    std::printf("Test the speed of HAVAL (PASS = %u, FPTLEN = %u bits).\n", pass_cnt, fpt_len);
    std::printf("Hashing %d %d-byte blocks ...\n", blocks_cnt, block_size);

    // initialize test block
    for (i = 0; i < block_size; i++) {
        buff[i] = static_cast<unsigned char>(~0);
    }

    // reset the clock
    clock();

    // hash
    hasher.start();
    for (i = 0; i < blocks_cnt; i++) {
        hasher.update(buff.get(), block_size);
    }
    fingerprint = hasher.end();

    // get the number of clocks
    clks = clock();
    // get cpu time
    cpu_time = static_cast<double>(clks) / static_cast<double>(CLOCKS_PER_SEC);

    if (cpu_time > 0.0) {
        std::printf("CPU Time = %3.1f seconds\n", cpu_time);
        std::printf("   Speed = %4.2f MBPS (megabits/second)\n", (blocks_cnt * block_size * 8) / (1.0E6 * cpu_time));
    } else {
        std::printf("not enough blocks !\n");
    }
}

// test endianity
int little_endian()
{
    haval::detail::word_t* wp;
    unsigned char str[4] = {'A', 'B', 'C', 'D'};

    wp = (haval::detail::word_t*)str;
    if (str[0] == static_cast<unsigned char>(*wp & 0xFF)) {
        // little endian
        return (1);
    } else {
        // big endian
        return (0);
    }
}

// print a fingerprint in hexadecimal
void haval_print(const std::string& fingerprint)
{
    for (std::size_t i = 0; i < fingerprint.size(); i++) {
        std::printf("%02X", static_cast<unsigned char>(fingerprint[i]));
    }
}

// print usage
void usage(unsigned int pass_cnt, unsigned int fpt_len)
{
    std::fprintf(stderr, "Usage: haval [OPTION] [FILE]...\n");
    std::fprintf(stderr, "  or:  haval -m [STRING]\n");
    std::fprintf(stderr, "Generates HAVAL hashes.\n");
    std::fprintf(stderr, "With no FILE, read standard input.\n\n");
    std::fprintf(stderr, "Configured to use %u passes and a %u-bit fingerprint length.\n\n", pass_cnt, fpt_len);
    std::fprintf(stderr, "    ?/-?/-h    show help menu\n");
    std::fprintf(stderr, "    -e         test endianity\n");
    std::fprintf(stderr, "    -m string  hash the given string\n");
    std::fprintf(stderr, "    -s         test speed\n");
    std::fprintf(stderr, "\nReport bugs to <info@calyptix.com>.\n");
}

template<unsigned int pass_cnt, unsigned int fpt_len>
int main_impl(int argc, char* argv[])
{
    using hash = haval::haval<pass_cnt, fpt_len>;

    int i;

    if (argc <= 1) {
        // filter
        haval_print(hash::from_stream(std::cin));
        std::printf("\n");
    }
    for (i = 1; i < argc; i++) {
        if ((argv[i][0] == '?') || (argv[i][0] == '-' && argv[i][1] == '?') || (argv[i][0] == '-' && argv[i][1] == 'h')) {
            // show help info
            usage(pass_cnt, fpt_len);
        } else if (argv[i][0] == '-' && argv[i][1] == 'm') {
            // hash string
            std::printf("HAVAL(\"%s\") = ", argv[i] + 2);
            haval_print(hash::from_string(argv[i] + 2));
            std::printf("\n");
        } else if (std::strcmp(argv[i], "-s") == 0) {
            // test speed
            haval_speed<pass_cnt, fpt_len>();
        } else if (std::strcmp(argv[i], "-e") == 0) {
            // test endianity
            if (little_endian()) {
                std::printf("Your machine is little-endian.\n");
                std::printf("You may define HAVAL_LITTLE_ENDIAN to speed up processing.\n");
            } else {
                std::printf("Your machine is NOT little-endian.\n");
                std::printf("You must NOT define HAVAL_LITTLE_ENDIAN.\n");
            }
        } else {
            // hash file
            std::ifstream f(argv[i], std::ios::in | std::ios::binary);
            if (!f.good()) {
                std::printf("%s can not be opened !\n= ", argv[i]);
            } else {
                std::printf("HAVAL(%s) = ", argv[i]);
                haval_print(hash::from_stream(f));
                std::printf("\n");
            }
        }
    }
    return (0);
}

template<unsigned int pass_cnt>
int main_impl(unsigned int fpt_len, int argc, char* argv[])
{
    switch (fpt_len) {
    case 128:
        return main_impl<pass_cnt, 128>(argc, argv);
    case 160:
        return main_impl<pass_cnt, 160>(argc, argv);
    case 192:
        return main_impl<pass_cnt, 192>(argc, argv);
    case 224:
        return main_impl<pass_cnt, 224>(argc, argv);
    case 256:
    default:
        return main_impl<pass_cnt, 256>(argc, argv);
    }
}

int main_impl(unsigned int pass_cnt, unsigned int fpt_len, int argc, char* argv[])
{
    switch (pass_cnt) {
    case 3:
    default:
        return main_impl<3>(fpt_len, argc, argv);
    case 4:
        return main_impl<4>(fpt_len, argc, argv);
    case 5:
        return main_impl<5>(fpt_len, argc, argv);
    }
}

} // namespace

int main(int argc, char* argv[])
{
    return main_impl(get_env_uint("HAVAL_PASS", 3), get_env_uint("HAVAL_FPTLEN", 256), argc, argv);
}
