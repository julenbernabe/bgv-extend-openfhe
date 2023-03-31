// Created on February 13 2023
// By Julen Bernabe Rodriguez <julen.bernabe@tecnalia.com>
// Copyright (c) 2023 Tecnalia Research & Innovation

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

/*
 * Computes vector of ciphertexts containing: {c^{2⁰}, c^{2¹}, c^{2²}, ..., c^{2^{length(binaryRep}}}
 * 
 */
std::vector<Ciphertext<DCRTPoly>> powersOfTwo(Ciphertext<DCRTPoly> ciphertext, uint binaryRepresentationLength, cryptoTools cc) {
    // Initialize vector of ciphertexts containing: {c^{2⁰}, c^{2¹}, c^{2²}, ..., c^{2^{length(binaryRep}}}
    std::vector<Ciphertext<DCRTPoly>> preComputedValues;
    
    // Add c^{2⁰} = c to preComputedValues
    preComputedValues.push_back(ciphertext);

    // Fill preComputedValues with remaining powers
    for (uint i = 1; i <= binaryRepresentationLength; i++) {
        preComputedValues.push_back(cc.cryptoContext->EvalMult(preComputedValues[i-1], preComputedValues[i-1]));
    }
    return preComputedValues;
}

/*
 * Computes array of powers of ciphertexts: {c¹, c², ..., c^{p-1}}
 * 
 */
std::vector<Ciphertext<DCRTPoly>> powers(Ciphertext<DCRTPoly> ciphertext, cryptoTools cc) {
    uint max = (cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus()) - 1;

    // Compute binary representation of exponent
    std::vector<uint> binaryRep = binaryRepresentationOfExp(max);

    // Compute vector {c^{2⁰}, c^{2¹}, c^{2²}, ..., c^{2^{length(binaryRep}}}
    std::vector<Ciphertext<DCRTPoly>> preComputedValues = powersOfTwo(ciphertext, binaryRep.size(), cc);

    // Structure containing the result
    std::vector<Ciphertext<DCRTPoly>> result;

    // Iterate over the exponents of c    
    for (uint i = 1; i <= max; i++) {
        // Compute binary representation of exponent
        std::vector<uint> binaryRep = binaryRepresentationOfExp(i);

        // Create new ciphertext to compute the result. Ciphertext is initialized by encrypting a 1.
        std::vector<int64_t> vectorOfOne = {1};
        Plaintext plaintextOne               = cc.cryptoContext->MakePackedPlaintext(vectorOfOne);
        Ciphertext<DCRTPoly> ciphertextResult = cc.cryptoContext->Encrypt(cc.keyPair.publicKey, plaintextOne);

        // Compute encrypted results using preComputedValues
        for (uint j = 0; j <= binaryRep.size(); j++) {
            if (binaryRep[j] == 1) {
                ciphertextResult = cc.cryptoContext->EvalMult(ciphertextResult, preComputedValues[j]);
            }
        }
        result.push_back(ciphertextResult);
    }
    return result;   
}