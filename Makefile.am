#  Copyright (c) 2003 Calyptix Security Corporation
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#  3. Neither the name of Calyptix Security Corporation nor the
#     names of its contributors may be used to endorse or promote
#     products derived from this software without specific prior
#     written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

AUX_DIST              = $(ac_aux_dir)/config.guess \
                        $(ac_aux_dir)/config.sub \
                        $(ac_aux_dir)/install-sh \
                        $(ac_aux_dir)/ltconfig \
                        $(ac_aux_dir)/ltmain.sh \
                        $(ac_aux_dir)/mdate-sh \
                        $(ac_aux_dir)/missing \
                        $(ac_aux_dir)/mkinstalldirs

MAINTAINERCLEANFILES  = Makefile.in aclocal.m4 configure config-h.in \
                        stamp-h.in $(AUX_DIST)

EXTRA_DIST           = VERSION pi.frac haval.cert cert.data ChangeLog \
                       TODO COPYING.BSD INSTALL haval-paper.pdf

INCLUDES             = -I$(top_builddir) -I$(top_srcdir)

bin_PROGRAMS         = haval

haval_SOURCES        = havaltest.c haval.c havalapp.h haval.h

haval_CFLAGS        = -Wall -ansi
 

