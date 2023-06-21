// Created on February 13 2023
// By Julen Bernabe Rodriguez <julen.bernabe@tecnalia.com>
// Copyright (c) 2023 Tecnalia Research & Innovation

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
            result = result * preComputedValues[i] % p;
        }
    }

    return result % p;   
}

int inverse(int n, int p) {
    return clearPower(n, p-2, p);
}