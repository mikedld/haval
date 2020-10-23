/*
 *  havaltest.cpp:  specifies a test program for the HAVAL hashing library.
 *
 *  Copyright (c) 2003 Calyptix Security Corporation
 *  All rights reserved.
 *
 *  This code is derived from software contributed to Calyptix Security
 *  Corporation by Yuliang Zheng.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *  3. Neither the name of Calyptix Security Corporation nor the
 *     names of its contributors may be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * -------------------------------------------------------------------
 *
 *  Arguments for the test program:
 *
 *      (none)    - hash input from stdin
 *      ?,-?,-h   - show help menu
 *      -e        - test whether your machine is little-endian
 *      -mstring  - hash message (string of chars)
 *      -s        - test speed
 *      file_name - hash file
 *
 *  Authors:    Yuliang Zheng and Lawrence Teo
 *              Calyptix Security Corporation
 *              P.O. Box 561508, Charlotte, NC 28213, USA
 *              Email: info@calyptix.com
 *              URL:   http://www.calyptix.com/
 *              Voice: +1 704 806 8635
 *
 *  For a list of changes, see the ChangeLog file.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "haval.h"

/* number of test blocks */
/* #define NUMBER_OF_BLOCKS 5000 */
/* number of bytes in a block */
/* #define BLOCK_SIZE 5000 */

/* test the speed of HAVAL */
static void haval_speed();
/* print a fingerprint */
static void haval_print(unsigned char*);
/* test endianity */
static int little_endian();
/* usage */
static void usage();

int main(int argc, char* argv[])
{
    int i;
    unsigned char fingerprint[FPTLEN >> 3];

    if (argc <= 1) {
        /* filter */
        haval_stdin();
    }
    for (i = 1; i < argc; i++) {
        if ((argv[i][0] == '?') || (argv[i][0] == '-' && argv[i][1] == '?') || (argv[i][0] == '-' && argv[i][1] == 'h')) {
            /* show help info */
            usage();
        } else if (argv[i][0] == '-' && argv[i][1] == 'm') {
            /* hash string */
            haval_string(argv[i] + 2, fingerprint);
            printf("HAVAL(\"%s\") = ", argv[i] + 2);
            haval_print(fingerprint);
            printf("\n");
        } else if (strcmp(argv[i], "-s") == 0) {
            /* test speed */
            haval_speed();
        } else if (strcmp(argv[i], "-e") == 0) {
            /* test endianity */
            if (little_endian()) {
                printf("Your machine is little-endian.\n");
                printf("You may define LITTLE_ENDIAN to speed up processing.\n");
            } else {
                printf("Your machine is NOT little-endian.\n");
                printf("You must NOT define LITTLE_ENDIAN.\n");
            }
        } else {
            /* hash file */
            if (haval_file(argv[i], fingerprint)) {
                printf("%s can not be opened !\n= ", argv[i]);
            } else {
                printf("HAVAL(%s) = ", argv[i]);
                haval_print(fingerprint);
                printf("\n");
            }
        }
    }
    return (0);
}

/* test the speed of HAVAL */
static void haval_speed()
{
    haval_state state;
    unsigned char buff[BLOCK_SIZE];
    unsigned char fingerprint[FPTLEN >> 3];
    clock_t clks;
    double cpu_time;
    unsigned int i;

    printf("Test the speed of HAVAL (PASS = %d, FPTLEN = %d bits).\n", PASS, FPTLEN);
    printf("Hashing %d %d-byte blocks ...\n", NUMBER_OF_BLOCKS, BLOCK_SIZE);

    /* initialize test block */
    for (i = 0; i < BLOCK_SIZE; i++) {
        buff[i] = (unsigned char)~0;
    }

    /* reset the clock */
    clock();

    /* hash */
    haval_start(&state);
    for (i = 0; i < NUMBER_OF_BLOCKS; i++) {
        haval_hash(&state, buff, BLOCK_SIZE);
    }
    haval_end(&state, fingerprint);

    /* get the number of clocks */
    clks = clock();
    /* get cpu time */
    cpu_time = (double)clks / (double)CLOCKS_PER_SEC;

    if (cpu_time > 0.0) {
        printf("CPU Time = %3.1f seconds\n", cpu_time);
        printf("   Speed = %4.2f MBPS (megabits/second)\n", (NUMBER_OF_BLOCKS * BLOCK_SIZE * 8) / (1.0E6 * cpu_time));
    } else {
        printf("not enough blocks !\n");
    }
}

/* test endianity */
static int little_endian()
{
    unsigned long* wp;
    unsigned char str[4] = {'A', 'B', 'C', 'D'};

    wp = (unsigned long*)str;
    if (str[0] == (unsigned char)(*wp & 0xFF)) {
        /* little endian */
        return (1);
    } else {
        /* big endian */
        return (0);
    }
}

/* print a fingerprint in hexadecimal */
static void haval_print(unsigned char fingerprint[FPTLEN >> 3])
{
    int i;

    for (i = 0; i < (FPTLEN >> 3); i++) {
        printf("%02X", fingerprint[i]);
    }
}

/* print usage */
static void usage()
{
    fprintf(stderr, "Usage: haval [OPTION] [FILE]...\n");
    fprintf(stderr, "  or:  haval -m [STRING]\n");
    fprintf(stderr, "Generates HAVAL hashes.\n");
    fprintf(stderr, "With no FILE, read standard input.\n\n");
    fprintf(stderr, "Compiled to use %d passes and a %d-bit fingerprint length.\n\n", PASS, FPTLEN);
    fprintf(stderr, "    ?/-?/-h    show help menu\n");
    fprintf(stderr, "    -e         test endianity\n");
    fprintf(stderr, "    -m string  hash the given string\n");
    fprintf(stderr, "    -s         test speed\n");
    fprintf(stderr, "\nReport bugs to <info@calyptix.com>.\n");
}
