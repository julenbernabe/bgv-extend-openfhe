//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
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
//==================================================================================

/*
 * Comparaciones en BGV
 */

#include "scheme/bgvrns/cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>
#include <time.h>

interpolationPoints integerPositiveDivisionPoints(int divisor, int p) {
    interpolationPoints ip;
    for (int i = 0; i < p; i++) {
        ip.x.push_back(i);
        ip.fx.push_back(i / divisor);
    }
    return ip;
}

interpolationPoints integerDivisionPoints(int divisor, int p) {
    interpolationPoints ip;
    for (int i = 0; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(i / divisor);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(-(p-i) / divisor);
        }
        
    }
    return ip;
}

Ciphertext<DCRTPoly> intPubDivision(Ciphertext<DCRTPoly> dividend, int divisor, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    if (divisor != 0) {
        std::vector<Ciphertext<DCRTPoly>> dividendPowers = powers(dividend, cc);
        interpolationPoints ip = integerDivisionPoints(divisor, p);
        std::vector<int64_t> poly = getLagrangePoly(ip, p);
        std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
        Ciphertext<DCRTPoly> evaluation = evalInterpolator(dividendPowers, cPoly, cc);
        return evaluation;
    } else {
        Ciphertext<DCRTPoly> evaluation = encrypt(divisor, cc);
        return evaluation; 
    }
}

Ciphertext<DCRTPoly> intPrivDivision(Ciphertext<DCRTPoly> dividend, Ciphertext<DCRTPoly> divisor, cryptoTools cc) {
    std::vector<Ciphertext<DCRTPoly>> dividendPowers = powers(dividend, cc);
    std::vector<Ciphertext<DCRTPoly>> divisorPowers = powers(divisor, cc);
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    Ciphertext<DCRTPoly> divResult = encrypt(0, cc);
    for (int i = 1; i < p; i++) {
        Ciphertext<DCRTPoly> ci = encrypt(i, cc);
        interpolationPoints ip = integerDivisionPoints(i, p);
        std::vector<int64_t> poly = getLagrangePoly(ip, p);
        std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
        Ciphertext<DCRTPoly> evaluation = evalInterpolator(dividendPowers, cPoly, cc);
        Ciphertext<DCRTPoly> equals = equal(ci, divisor, cc);
        Ciphertext<DCRTPoly> pre = cc.cryptoContext->EvalMult(evaluation, equals);
        divResult = cc.cryptoContext->EvalAdd(divResult, pre);
    }
    return divResult;
}


