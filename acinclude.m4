dnl  $Id: acinclude.m4,v 1.3 2003/01/20 05:44:48 lteo Exp $

dnl  acinclude.m4:  self-defined m4 macros.
dnl
dnl  Copyright (c) 2003 Calyptix Security Corporation
dnl  All rights reserved.
dnl
dnl  Redistribution and use in source and binary forms, with or without
dnl  modification, are permitted provided that the following conditions
dnl  are met:
dnl  1. Redistributions of source code must retain the above copyright
dnl     notice, this list of conditions and the following disclaimer.
dnl  2. Redistributions in binary form must reproduce the above
dnl     copyright notice, this list of conditions and the following
dnl     disclaimer in the documentation and/or other materials provided
dnl     with the distribution.
dnl  3. Neither the name of Calyptix Security Corporation nor the
dnl     names of its contributors may be used to endorse or promote
dnl     products derived from this software without specific prior
dnl     written permission.
dnl
dnl THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
dnl "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
dnl LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
dnl FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
dnl COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
dnl INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
dnl BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
dnl LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
dnl CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
dnl LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
dnl ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
dnl POSSIBILITY OF SUCH DAMAGE.
dnl
dnl -------------------------------------------------------------------


dnl Check endianness
AC_DEFUN(AC_CALYPTIX_ENDIAN_CHECK,
    [AC_MSG_CHECKING(machine endianess)

    cat > conftest.c << EOF
        /* test endianity */
        int main()
        {
            unsigned long *wp;
            unsigned char str[[4]] = {'A', 'B', 'C', 'D'};

            wp = (unsigned long *)str;
            if (str[[0]] == (unsigned char)( *wp & 0xFF)) {
                printf("L");                       /* little endian */
            } else {
                printf("B");                       /* big endian */
            }
        }
EOF
        ${CC-cc} -o conftest $CFLAGS $CPPFLAGS $LDFLAGS conftest.c $LIBS > /dev/null 2>&1
        if test ! -x conftest ; then
dnl failed to compile for some reason
            ac_cv_calyptix_endianess=unknown
        else
            ./conftest > conftest.out
            result=`cat conftest.out`
            if test $result = "B"; then
                ac_cv_calyptix_endianess=big
            elif test $result = "L"; then
                ac_cv_calyptix_endianess=little
            else
                ac_cv_calyptix_endianess=unknown
            fi                                
        fi
        rm -f conftest* core core.conftest

        AC_MSG_RESULT($ac_cv_calyptix_endianess)

        if test $ac_cv_calyptix_endianess = little ; then
            AC_DEFINE_UNQUOTED(LITTLE_ENDIAN, 1, [Little-endian])
        fi

#         if test $ac_cv_calyptix_endianess = big ; then
#             # AC_DEFINE(LIBNET_BIG_ENDIAN)
#             ENDIANESS="LIBNET_BIG_ENDIAN"
#             # LIBNET_CONFIG_DEFINES="$LIBNET_CONFIG_DEFINES -DLIBNET_BIG_ENDIAN"
#             CFLAGS=
#         elif test $ac_cv_calyptix_endianess = lil ; then
#             # AC_DEFINE(LIBNET_LIL_ENDIAN)
#             ENDIANESS="LIBNET_LIL_ENDIAN"
#             # LIBNET_CONFIG_DEFINES="$LIBNET_CONFIG_DEFINES -DLIBNET_LIL_ENDIAN"
#         fi
    ])
