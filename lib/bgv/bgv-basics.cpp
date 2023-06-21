// Created on February 13 2023
// By Julen Bernabe Rodriguez <julen.bernabe@tecnalia.com>
// Copyright (c) 2023 Tecnalia Research & Innovation

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
/** 
 * @brief Structure for storing X and Y sets from Step 1
 * 
 * @param x: array containing the elements of X
 * @param fx: array containing the elements of Y (the f(x)'s)
 */
struct Points {
    std::vector<int64_t> x;
    std::vector<int64_t> fx;
};

typedef struct Points interpolationPoints;

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



