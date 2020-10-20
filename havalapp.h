/*
 *  havalapp.h:  specifies the following three constants needed to
 *               compile the HAVAL hashing library:
 *                     LITTLE_ENDIAN, PASS and FPTLEN
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
 *  Descriptions:
 *
 *   LITTLE_ENDIAN  define this only if your machine is little-endian
 *                  (such as 80X86 family). 
 *
 *         Note:
 *            1. In general, HAVAL is faster on a little endian
 *               machine than on a big endian one.
 *
 *            2. The test program "havaltest.c" provides an option
 *               for testing the endianity of your machine.
 *
 *            3. The speed of HAVAL is even more remarkable on a
 *               machine that has a large number of internal registers.
 *
 *   PASS     define the number of passes        (3, 4, or 5)
 *   FPTLEN   define the length of a fingerprint (128, 160, 192, 224 or 256)
 */

#include "config.h"

#ifdef THIS_IS_JUST_A_DUMMY_DIRECTIVE

#undef LITTLE_ENDIAN

#ifndef PASS
#define PASS       3        /* 3, 4, or 5 */
#endif


#ifndef FPTLEN  
#define FPTLEN     256      /* 128, 160, 192, 224 or 256 */
#endif

#endif /* THIS_IS_JUST_A_DUMMY_DIRECTIVE */


