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

#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <time.h>

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
    const unsigned int blocks_cnt = get_env_uint("HAVAL_NUMBER_OF_BLOCKS", 5000);
    const unsigned int block_size = get_env_uint("HAVAL_BLOCK_SIZE", 5000);

    std::cout << "Test the speed of HAVAL (PASS = " << pass_cnt << ", FPTLEN = " << fpt_len << " bits)." << std::endl;
    std::cout << "Hashing " << blocks_cnt << " " << block_size << "-byte blocks ..." << std::endl;

    // initialize test block
    const std::unique_ptr<std::uint8_t[]> buff(new std::uint8_t[block_size]);
    for (unsigned int i = 0; i < block_size; i++) {
        buff[i] = static_cast<std::uint8_t>(~0);
    }

    haval::haval<pass_cnt, fpt_len> hasher;
    std::string fingerprint;

    // reset the clock
    clock();

    // hash
    hasher.start();
    for (unsigned int i = 0; i < blocks_cnt; i++) {
        hasher.update(buff.get(), block_size);
    }
    fingerprint = hasher.end();

    // get the number of clocks
    const clock_t clks = clock();
    // get cpu time
    const double cpu_time = static_cast<double>(clks) / static_cast<double>(CLOCKS_PER_SEC);

    if (cpu_time > 0.0) {
        std::cout << "CPU Time = " << std::fixed << std::setprecision(1) << cpu_time << " seconds" << std::endl;
        std::cout << "   Speed = " << std::fixed << std::setprecision(2) << ((blocks_cnt * block_size * 8) / (1.0E6 * cpu_time))
                  << " MBPS (megabits/second)" << std::endl;
    } else {
        std::cout << "not enough blocks !" << std::endl;
    }
}

// test endianity
bool little_endian()
{
    const std::uint8_t str[4] = {'A', 'B', 'C', 'D'};
    const haval::detail::word_t* wp = reinterpret_cast<const haval::detail::word_t*>(str);
    return str[0] == static_cast<std::uint8_t>(*wp & 0xFF);
}

// print a fingerprint in hexadecimal
std::string to_hex(const std::string& fingerprint)
{
    std::ostringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (char c : fingerprint) {
        stream << std::setw(2) << int{static_cast<std::uint8_t>(c)};
    }
    return stream.str();
}

// print usage
void usage(unsigned int pass_cnt, unsigned int fpt_len)
{
    std::cerr << "Usage: haval [OPTION] [FILE]..." << std::endl
              << "  or:  haval -m [STRING]" << std::endl
              << "Generates HAVAL hashes." << std::endl
              << "With no FILE, read standard input." << std::endl
              << std::endl
              << "Configured to use " << pass_cnt << " passes and a " << fpt_len << "-bit fingerprint length." << std::endl
              << std::endl
              << "    ?/-?/-h    show help menu" << std::endl
              << "    -e         test endianity" << std::endl
              << "    -m string  hash the given string" << std::endl
              << "    -s         test speed" << std::endl
              << std::endl
              << "Report bugs to <info@calyptix.com>." << std::endl;
}

template<unsigned int pass_cnt, unsigned int fpt_len>
int main_impl(int argc, char* argv[])
{
    using hash = haval::haval<pass_cnt, fpt_len>;

    if (argc <= 1) {
        // filter
        std::cout << to_hex(hash::from_stream(std::cin)) << std::endl;
    }

    for (int i = 1; i < argc; i++) {
        const std::string arg = argv[i];

        if (arg == "?" || arg == "-?" || arg == "-h") {
            // show help info
            usage(pass_cnt, fpt_len);
        } else if (arg.compare(0, 2, "-m") == 0) {
            // hash string
            const std::string data = arg.substr(2);
            std::cout << "HAVAL(" << std::quoted(data) << ") = " << to_hex(hash::from_string(data)) << std::endl;
        } else if (arg == "-s") {
            // test speed
            haval_speed<pass_cnt, fpt_len>();
        } else if (arg == "-e") {
            // test endianity
            if (little_endian()) {
                std::cout << "Your machine is little-endian." << std::endl;
                std::cout << "You may define HAVAL_LITTLE_ENDIAN to speed up processing." << std::endl;
            } else {
                std::cout << "Your machine is NOT little-endian." << std::endl;
                std::cout << "You must NOT define HAVAL_LITTLE_ENDIAN." << std::endl;
            }
        } else {
            // hash file
            std::ifstream f(arg.c_str(), std::ios::in | std::ios::binary);
            if (!f.good()) {
                std::cout << arg << " can not be opened !" << std::endl;
            } else {
                std::cout << "HAVAL(" << arg << ") = " << to_hex(hash::from_stream(f)) << std::endl;
            }
        }
    }

    return 0;
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
