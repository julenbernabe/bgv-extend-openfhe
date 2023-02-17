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
 * BGV basics
 */

#include "scheme/bgvrns/cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

using namespace lbcrypto;

struct crypto {
    CryptoContext<DCRTPoly> cryptoContext;
    KeyPair<DCRTPoly> keyPair;
};

typedef struct crypto cryptoTools;

/*
 * Context setup utility methods
 */
CryptoContext<DCRTPoly> GenerateBGVrnsContext(usint ptm, usint multDepth, usint level) {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(level);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingTechnique(FIXEDAUTO);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    return cc;
}

cryptoTools genCryptoTools(usint p, usint level) {
    cryptoTools cc;

    // compute binary representation of p-1
    std::vector<uint> binaryRep = binaryRepresentationOfExp(p-1);
    
    // Define parameters of BGV cryptographic context
    usint ptm                  = p;
    usint depth                = binaryRep.size() + 1;      // Maximum depth needed is the binary representation of p-1

    // Generate context with above parameters
    cc.cryptoContext = GenerateBGVrnsContext(ptm, depth, level);

    // Key generation
    cc.keyPair = cc.cryptoContext->KeyGen();
    cc.cryptoContext->EvalMultKeyGen(cc.keyPair.secretKey);
    cc.cryptoContext->EvalSumKeyGen(cc.keyPair.secretKey);
    return cc;
}

Ciphertext<DCRTPoly> encryptV(std::vector<int64_t> v, cryptoTools cc) {

    // Encode vector as plaintext
    Plaintext plaintext               = cc.cryptoContext->MakePackedPlaintext(v);

    // Encrypt plaintext
    Ciphertext<DCRTPoly> ciphertext   = cc.cryptoContext->Encrypt(cc.keyPair.publicKey, plaintext);
    return ciphertext;
}

Ciphertext<DCRTPoly> encrypt(int n, cryptoTools cc) {
    // Generate vector with the integer
    std::vector<int64_t> vectorOfInts = {n};

    // Encode vector as plaintext
    Plaintext plaintext               = cc.cryptoContext->MakePackedPlaintext(vectorOfInts);

    // Encrypt plaintext
    Ciphertext<DCRTPoly> ciphertext   = cc.cryptoContext->Encrypt(cc.keyPair.publicKey, plaintext);
    return ciphertext;
}

std::vector<int64_t> decrypt(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    // Initialize plaintext for result
    Plaintext plaintextResult;
    cc.cryptoContext->Decrypt(cc.keyPair.secretKey, c, &plaintextResult);
    std::vector<int64_t> result = plaintextResult->GetPackedValue();
    return result;
}



