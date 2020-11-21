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

#include "haval-qt.hpp"

#include <QByteArray>
#include <QFile>
#include <QtGlobal>

#include <iostream>

QT_USE_NAMESPACE

using haval::QHaval;

int main()
{
    int exit_code = 0;

    {
        QHaval<3, 128> haval;
        haval.start();
        haval.update("HAVAL", 5);
        if (haval.end() != QByteArray::fromHex(QByteArrayLiteral("DC1F3C893D17CC4EDD9AE94AF76A0AF0"))) {
            exit_code = 1;
        }
    }

    {
        if (QHaval<4, 192>::hash(QByteArrayLiteral("abcdefghijklmnopqrstuvwxyz")) !=
            QByteArray::fromHex(QByteArrayLiteral("2E2E581D725E799FDA1948C75E85A28CFE1CF0C6324A1ADA"))) {
            exit_code = 1;
        }
    }

    {
        QFile file(QStringLiteral("pi.frac"));
        if (!file.open(QFile::ReadOnly) ||
            QHaval<5, 256>::hash(&file) !=
                    QByteArray::fromHex(
                            QByteArrayLiteral("AABF0B45AC4A4E84268F50ABCC3EF3806BCC9860EA6A92425F537C46A957963A"))) {
            exit_code = 1;
        }
    }

    return exit_code;
}
