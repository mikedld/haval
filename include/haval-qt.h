// Copyright (c) 2020, Mike Gelfand
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

#include <QtGlobal>

QT_BEGIN_NAMESPACE

class QByteArray;
class QIODevice;

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
class QByteArrayView;
#endif

QT_END_NAMESPACE

namespace haval
{

template<unsigned int pass_cnt, unsigned int fpt_len>
class QHaval
{
public:
    using impl_type = haval<pass_cnt, fpt_len>;

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    using size_type = QT_PREPEND_NAMESPACE(qsizetype);
#else
    using size_type = int;
#endif

    static constexpr size_type result_size = static_cast<int>(fpt_len) >> 3;

public:
    // initialization
    void start();
    // updating routine
    void update(const void* data, size_type data_len);
    // finalization
    void endTo(void* data);
    QT_PREPEND_NAMESPACE(QByteArray) end();

    // hash a block
    static QT_PREPEND_NAMESPACE(QByteArray) hash(const void* data, size_type data_len);
    // hash a byte array
    static QT_PREPEND_NAMESPACE(QByteArray) hash(const QT_PREPEND_NAMESPACE(QByteArray)& data);
    // hash a stream
    static QT_PREPEND_NAMESPACE(QByteArray) hash(QT_PREPEND_NAMESPACE(QIODevice)* device);

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    // hash a byte array view
    static QT_PREPEND_NAMESPACE(QByteArray) hash(const QT_PREPEND_NAMESPACE(QByteArrayView)& data);
#endif

private:
    impl_type m_impl;
};

} // namespace haval
