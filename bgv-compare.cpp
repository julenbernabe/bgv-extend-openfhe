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
#include "lib.h"
#include "bgv-basics.h"
#include "bgv-power.h"
#include "bgv-interpolation.h"
#include "bgv-compare.h"
#include "bgv-int-division.h"

using namespace lbcrypto;


void stringComparator() {

    std::cout << "\nBGV STRING COMPARATOR\n "<< std::endl;

    // -------------------- CLIENT SIDE --------------------

    std::string first, second;
    std::cout << "Enter two words: "<< std::endl;
    std::cout << "\t - First word: ";
    std::cin >> first;
    std::cout << "\t - Second word: ";
    std::cin >> second;

    // First string
    std::vector<int64_t> firstV;
    for (uint i = 0; i < first.length(); i++) {
        firstV.push_back(int64_t(first[i]));
    }

    // Second string
    std::vector<int64_t> secondV;
    for (uint i = 0; i < second.length(); i++) {
        secondV.push_back(int64_t(second[i]));
    }
    
    cryptoTools cc = genCryptoTools(257, 16);

    Ciphertext<DCRTPoly> c3 = encryptV(firstV, cc);
    Ciphertext<DCRTPoly> c4 = encryptV(secondV, cc);

    // -----------------------------------------------------

    // Here the ciphertexts are sent to the server

    // -------------------- SERVER SIDE --------------------
    time_t timer3;
    time_t timer4;
    double seconds1;
    time(&timer3);
    usint batchSize = 16;
    Ciphertext<DCRTPoly> resultV = equalV(c3, c4, batchSize, cc);
    time(&timer4);
    seconds1 = difftime(timer4,timer3);

    // -----------------------------------------------------

    // Here the result is sent to the client

    // -------------------- CLIENT SIDE --------------------

    std::vector<int64_t> result = decrypt(resultV, cc);
    std::cout << "\nNumber of different letters: " << result[0] << std::endl;
    if (result[0] == 0) {
        std::cout << "Words are equal!" << std::endl;
    }
    std::cout << "\nTime used to compare: " << seconds1 << " seconds "<< std::endl;
}

void getSign() {

    std::cout << "\nBGV GET SIGN\n "<< std::endl;

    // -------------------- CLIENT SIDE --------------------
    cryptoTools cc = genCryptoTools(257, 2);
    int first;
    std::cout << "Enter integer to obtain sign: "<< std::endl;
    std::cin >> first;

    Ciphertext<DCRTPoly> c1 = encrypt(first, cc);

    // -----------------------------------------------------

    // Here the ciphertexts are sent to the server

    // -------------------- SERVER SIDE --------------------
    time_t timer1;
    time_t timer2;
    double seconds;
    time(&timer1);
    Ciphertext<DCRTPoly> cSign = sign(c1, cc);
    time(&timer2);
    seconds = difftime(timer2,timer1);

    // -----------------------------------------------------

    // Here the result is sent to the client

    // -------------------- CLIENT SIDE --------------------

    std::vector<int64_t> result = decrypt(cSign, cc);
    std::cout << "\nResult: "<< result[0] << std::endl;
    std::cout << "\nTime used to compute: " << seconds << " seconds "<< std::endl;
}


void intComparator() {

    std::cout << "\nBGV INTEGER COMPARATOR\n "<< std::endl;

    // -------------------- CLIENT SIDE --------------------
    cryptoTools cc = genCryptoTools(257, 2);
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    int first, second;
    std::cout << "Enter two integers: "<< std::endl;
    std::cout << "\t - First integer: ";
    std::cin >> first;
    while (first > (p-1)/2) {
        std::cout << "\nInteger must be between " << -(p - 1) / 2 << " and " << (p - 1) / 2 << std::endl;
        std::cout << "First integer: ";
        std::cin >> first;
    }
    while (first < -(p-1)/2) {
        std::cout << "\nInteger must be between " << -(p - 1) / 2 << " and " << (p - 1) / 2 << std::endl;
        std::cout << "First integer: ";
        std::cin >> first;
    }
    std::cout << "\t - Second integer: ";
    std::cin >> second;
    while (second > (p-1)/2) {
        std::cout << "\nInteger must be between " << -(p - 1) / 2 << " and " << (p - 1) / 2 << std::endl;
        std::cout << "Second integer: ";
        std::cin >> second;
    }
    while (second < -(p-1)/2) {
        std::cout << "\nInteger must be between " << -(p - 1) / 2 << " and " << (p - 1) / 2 << std::endl;
        std::cout << "Second integer: ";
        std::cin >> second;
    }

    Ciphertext<DCRTPoly> c1 = encrypt(first, cc);
    Ciphertext<DCRTPoly> c2 = encrypt(second, cc);

    // -----------------------------------------------------

    // Here the ciphertexts are sent to the server

    // -------------------- SERVER SIDE --------------------
    time_t timer1;
    time_t timer2;
    double seconds;
    time(&timer1);
    Ciphertext<DCRTPoly> cEq = equal(c1, c2, cc);
    Ciphertext<DCRTPoly> cGreater = gt(c1, c2, cc);
    Ciphertext<DCRTPoly> cGreaterEq = gteq(c1, c2, cc);
    Ciphertext<DCRTPoly> cLower = lt(c1, c2, cc);
    Ciphertext<DCRTPoly> cLowerEq = lteq(c1, c2, cc);
    Ciphertext<DCRTPoly> cMax = max(c1, c2, cc);
    Ciphertext<DCRTPoly> cMin = min(c1, c2, cc);
    time(&timer2);
    seconds = difftime(timer2,timer1);

    // -----------------------------------------------------

    // Here the result is sent to the client

    // -------------------- CLIENT SIDE --------------------

    std::vector<int64_t> rEq = decrypt(cEq, cc);
    std::vector<int64_t> rGreater = decrypt(cGreater, cc);
    std::vector<int64_t> rGreaterEq = decrypt(cGreaterEq, cc);
    std::vector<int64_t> rLower = decrypt(cLower, cc);
    std::vector<int64_t> rLowerEq = decrypt(cLowerEq, cc);
    std::vector<int64_t> rMax = decrypt(cMax, cc);
    std::vector<int64_t> rMin = decrypt(cMin, cc);
    std::cout << first << " == " << second << ": " << rEq[0] << std::endl;
    std::cout << first << " > " << second << ": " << rGreater[0] << std::endl;
    std::cout << first << " >= " << second << ": " << rGreaterEq[0] << std::endl;
    std::cout << first << " < " << second << ": " << rLower[0] << std::endl;
    std::cout << first << " <= " << second << ": " << rLowerEq[0] << std::endl;
    std::cout << "max(" << first << ", " <<  second << ") = " << rMax[0] << std::endl;
    std::cout << "min(" << first << ", " <<  second << ") = " << rMin[0] << std::endl;
    std::cout << "\nTime used to compute: " << seconds << " seconds "<< std::endl;
}

std::string intro() {

    std::cout << "\n\n############# BGV COMPARATOR #############\n\n"<< std::endl;
    std::cout << "Choose between:"<< std::endl;
    std::cout << "\t - Integer comparison (IC)"<< std::endl;
    std::cout << "\t - String comparison (SC)"<< std::endl;
    std::cout << "\t - Sign of number (S)"<< std::endl;
    std::cout << "\t - Quit (Q)"<< std::endl;
    std::string operation;
    std::cin >> operation;
    return operation;
}

int main() {

    std::string operation = intro();
    while (operation != "Q") {
        if (operation == "IC") {
            intComparator();
        } else if (operation == "SC") {
            stringComparator();
        } else if (operation == "S") {
            getSign();
        } else {
            std::cout << "Please, introduce a valid value."<< std::endl;
        }
        operation = intro();
    }
}