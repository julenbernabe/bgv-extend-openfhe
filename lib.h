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
 * Library with basic functions
 */

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

std::vector<uint> binaryRepresentationOfExp(uint n) {
    // Calculamos binary representation de n
    uint remainder = 0;
    uint newN = n;
    std::vector<uint> binaryRepOfN;
    while (newN > 0) {
        remainder = newN % 2;
        binaryRepOfN.push_back(remainder);
        newN = newN / 2;
    }
    return binaryRepOfN;
}

/*
 * Computes vector of uints containing: {c^{2⁰}, c^{2¹}, c^{2²}, ..., c^{2^{length(binaryRep}}}
 * 
 */
std::vector<int> clearPowersOfTwo(int n, int binaryRepresentationLength, int p) {
    // Initialize vector of ciphertexts containing: {c^{2⁰}, c^{2¹}, c^{2²}, ..., c^{2^{length(binaryRep}}}
    std::vector<int> preComputedValues;
    
    // Add c^{2⁰} = c to preComputedValues
    preComputedValues.push_back(n);

    // Fill preComputedValues with remaining powers
    for (int i = 1; i <= binaryRepresentationLength; i++) {
        preComputedValues.push_back((preComputedValues[i-1] * preComputedValues[i-1]) % p);
    }
    return preComputedValues;
}

/*
 * Computes powers of integers mod p. Both the base and the exponent are public.
 * 
 */
int clearPower(int n, int exp, int p) {
    // Compute binary representation of exponent
    std::vector<uint> binaryRep = binaryRepresentationOfExp(exp);

    // Compute vector {c^{2⁰}, c^{2¹}, c^{2²}, ..., c^{2^{length(binaryRep}}}
    std::vector<int> preComputedValues = clearPowersOfTwo(n, binaryRep.size(), p);

    int result = 1;
    // Compute encrypted result using preComputedValues
    for (uint i = 0; i <= binaryRep.size(); i++) {
        if (binaryRep[i] == 1) {
            result = result * preComputedValues[i];
        }
    }

    return result % p;   
}

int inverse(int n, int p) {
    return clearPower(n, p-2, p);
}