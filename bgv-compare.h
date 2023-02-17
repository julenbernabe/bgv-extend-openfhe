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

using namespace lbcrypto;


Ciphertext<DCRTPoly> equal(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute difference = c1 - c2
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);
    
    // Compute f = a^{p-1}. By Fermat's Little Theorem: 
    //      - If a != 0 then f = 1
    //      - If a = 0 then f = 0
    Ciphertext<DCRTPoly> f = power(difference, (cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus()) - 1, cc);

    // Want to invert the result now, i.e., if c1 == c2 return 1, not 0. For that we do: (-f) + 1.
    // Observe that:
    //      - If f = 0: r = (-f) + 1 = 0 + 1 = 1
    //      - If f = 1: r = (-f) + 1 = -1 + 1 = 0

    // Compute fNeg = -f
    Ciphertext<DCRTPoly> fNeg = cc.cryptoContext->EvalNegate(f);

    // Create ciphertext with value 1:
    std::vector<int64_t> vectorOfOne = {1};
    Plaintext plaintextOne               = cc.cryptoContext->MakePackedPlaintext(vectorOfOne);
    Ciphertext<DCRTPoly> cOne = cc.cryptoContext->Encrypt(cc.keyPair.publicKey, plaintextOne);

    // Compute fNeg + cOne = fNeg + 1
    Ciphertext<DCRTPoly> result = cc.cryptoContext->EvalAdd(fNeg, cOne);
    return result;
}

Ciphertext<DCRTPoly> equalV(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, usint batchSize, cryptoTools cc) {
    // Compute difference = c1 - c2
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);
    
    // Compute f = a^{p-1}. By Fermat's Little Theorem: 
    //      - If a != 0 then f = 1
    //      - If a = 0 then f = 0
    Ciphertext<DCRTPoly> pref = powerV(difference, (cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus()) - 1, batchSize, cc);

    // Compute the sum of the first n components (batchSize = n)
    Ciphertext<DCRTPoly> result = cc.cryptoContext->EvalSum(pref, batchSize);

    return result;
}

interpolationPoints evalSignPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(0);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(1);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(-1);
        }  
    }
    return ip;
}

interpolationPoints evalGreaterPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(0);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(1);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(0);
        }  
    }
    return ip;
}

interpolationPoints evalGreaterEqualPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(1);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(1);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(0);
        }  
    }
    return ip;
}

interpolationPoints evalLowerPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(0);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(0);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(1);
        }  
    }
    return ip;
}

interpolationPoints evalLowerEqualPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(1);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(0);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(1);
        }  
    }
    return ip;
}

Ciphertext<DCRTPoly> sign(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalSignPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> greaterThanZero(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalGreaterPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> greaterEqualThanZero(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalGreaterEqualPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> lowerThanZero(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalLowerPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> lowerEqualThanZero(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalLowerEqualPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> gt(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute the difference
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);

    // Check if it is greater than 0 or not
    Ciphertext<DCRTPoly> result = greaterThanZero(difference, cc);

    return result;
}

Ciphertext<DCRTPoly> gteq(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute the difference
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);

    // Check if it is greater than 0 or not
    Ciphertext<DCRTPoly> result = greaterEqualThanZero(difference, cc);

    return result;
}

Ciphertext<DCRTPoly> lt(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute the difference
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);

    // Check if it is greater than 0 or not
    Ciphertext<DCRTPoly> result = lowerThanZero(difference, cc);

    return result;
}

Ciphertext<DCRTPoly> lteq(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute the difference
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);

    // Check if it is greater than 0 or not
    Ciphertext<DCRTPoly> result = lowerEqualThanZero(difference, cc);

    return result;
}

Ciphertext<DCRTPoly> max(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute d1 = c1 - c2
    Ciphertext<DCRTPoly> d1 = cc.cryptoContext->EvalSub(c1, c2);

    // Check if d1 is greater than 0 or not
    Ciphertext<DCRTPoly> g1 = greaterEqualThanZero(d1, cc);

    // Compute d2 = c2 - c1
    Ciphertext<DCRTPoly> d2 = cc.cryptoContext->EvalSub(c2, c1);

    // Check if d2 is greater than 0 or not
    Ciphertext<DCRTPoly> g2 = greaterThanZero(d2, cc);

    // Formula = g1 x c1 + g2 x c2
    Ciphertext<DCRTPoly> r1 = cc.cryptoContext->EvalMult(g1, c1);
    Ciphertext<DCRTPoly> r2 = cc.cryptoContext->EvalMult(g2, c2);
    Ciphertext<DCRTPoly> result = cc.cryptoContext->EvalAdd(r1, r2);
    return result;
}

Ciphertext<DCRTPoly> min(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute d1 = c1 - c2
    Ciphertext<DCRTPoly> d1 = cc.cryptoContext->EvalSub(c1, c2);

    // Check if d1 is greater than 0 or not
    Ciphertext<DCRTPoly> g1 = lowerEqualThanZero(d1, cc);

    // Compute d2 = c2 - c1
    Ciphertext<DCRTPoly> d2 = cc.cryptoContext->EvalSub(c2, c1);

    // Check if d2 is greater than 0 or not
    Ciphertext<DCRTPoly> g2 = lowerThanZero(d2, cc);

    // Formula = g1 x c1 + g2 x c2
    Ciphertext<DCRTPoly> r1 = cc.cryptoContext->EvalMult(g1, c1);
    Ciphertext<DCRTPoly> r2 = cc.cryptoContext->EvalMult(g2, c2);
    Ciphertext<DCRTPoly> result = cc.cryptoContext->EvalAdd(r1, r2);
    return result;
}