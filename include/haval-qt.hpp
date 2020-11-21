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

#include "haval-qt.h"

#include "haval.hpp"

#include <QByteArray>
#include <QIODevice>

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
#include <QByteArrayView>
#endif

#include <limits>
#include <type_traits>

namespace haval
{

template<unsigned int pass_cnt, unsigned int fpt_len>
void QHaval<pass_cnt, fpt_len>::start()
{
    m_impl.start();
}

template<unsigned int pass_cnt, unsigned int fpt_len>
void QHaval<pass_cnt, fpt_len>::update(const void* data, size_type data_len)
{
    static_assert(sizeof(data_len) <= sizeof(typename impl_type::size_type), "size_type size mismatch");
    Q_ASSERT(data_len >= 0);

    m_impl.update(data, static_cast<typename impl_type::size_type>(data_len));
}

template<unsigned int pass_cnt, unsigned int fpt_len>
void QHaval<pass_cnt, fpt_len>::endTo(void* data)
{
    m_impl.end_to(data);
}

template<unsigned int pass_cnt, unsigned int fpt_len>
QT_PREPEND_NAMESPACE(QByteArray) QHaval<pass_cnt, fpt_len>::end()
{
    QT_PREPEND_NAMESPACE(QByteArray) result(result_size, '\0');
    endTo(result.data());
    return result;
}

template<unsigned int pass_cnt, unsigned int fpt_len>
QT_PREPEND_NAMESPACE(QByteArray) QHaval<pass_cnt, fpt_len>::hash(const void* data, size_type data_len)
{
    QHaval<pass_cnt, fpt_len> impl;
    impl.start();
    impl.update(data, data_len);
    return impl.end();
}

template<unsigned int pass_cnt, unsigned int fpt_len>
QT_PREPEND_NAMESPACE(QByteArray) QHaval<pass_cnt, fpt_len>::hash(const QT_PREPEND_NAMESPACE(QByteArray)& data)
{
    return hash(data.data(), data.size());
}

template<unsigned int pass_cnt, unsigned int fpt_len>
QT_PREPEND_NAMESPACE(QByteArray) QHaval<pass_cnt, fpt_len>::hash(QT_PREPEND_NAMESPACE(QIODevice)* device)
{
    Q_ASSERT(device != nullptr);
    Q_ASSERT(device->isReadable());

    QHaval<pass_cnt, fpt_len> impl;
    impl.start();

    char buffer[1024];

    for (;;) {
        const auto bytes_read = device->read(buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            break;
        }
        impl.update(buffer, static_cast<size_type>(bytes_read));
    }

    return impl.end();
}

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)

template<unsigned int pass_cnt, unsigned int fpt_len>
QT_PREPEND_NAMESPACE(QByteArray) QHaval<pass_cnt, fpt_len>::hash(const QT_PREPEND_NAMESPACE(QByteArrayView)& data)
{
    return hash(data.data(), data.size());
}

#endif

} // namespace haval
