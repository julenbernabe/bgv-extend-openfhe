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


std::string intro() {

    std::cout << "\n\n############# BGV INTEGER DIVISION #############\n\n"<< std::endl;
    std::cout << "Choose between:"<< std::endl;
    std::cout << "\t - Integer comparison (i)"<< std::endl;
    std::cout << "\t - String comparison (s)"<< std::endl;
    std::cout << "\t - Quit (q)"<< std::endl;
    std::string operation;
    std::cin >> operation;
    return operation;
}

void intDivision() {

    std::cout << "\nBGV INTEGER DIVISION\n "<< std::endl;

    // -------------------- CLIENT SIDE --------------------
    cryptoTools cc = genCryptoTools(257, 2);
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    int dividend, divisor;
    std::cout << "(Client) Enter dividend: ";
    std::cin >> dividend;
    while (dividend > (p-1)/2) {
        std::cout << "\nDividend must be between " << -(p - 1) / 2 << " and " << (p - 1) / 2 << std::endl;
        std::cout << "(Client) Enter dividend: ";
        std::cin >> dividend;
    }
    while (dividend < -(p-1)/2) {
        std::cout << "\nDividend must be between " << -(p - 1) / 2 << " and " << (p - 1) / 2 << std::endl;
        std::cout << "(Client) Enter dividend: ";
        std::cin >> dividend;
    }

    Ciphertext<DCRTPoly> cDividend = encrypt(dividend, cc);

    // -----------------------------------------------------

    // Here the ciphertexts are sent to the server

    // -------------------- SERVER SIDE --------------------
    std::cout << "(Server) Enter divisor:  ";
    std::cin >> divisor;
    while (divisor > (p-1)/2) {
        std::cout << "\nDivisor must be between " << -(p - 1) / 2 << " and " << (p - 1) / 2 << std::endl;
        std::cout << "(Server) Enter divisor: ";
        std::cin >> divisor;
    }
    while (divisor < -(p-1)/2) {
        std::cout << "\nDivisor must be between " << -(p - 1) / 2 << " and " << (p - 1) / 2 << std::endl;
        std::cout << "(Server) Enter divisor: ";
        std::cin >> divisor;
    }
    Ciphertext<DCRTPoly> cDivisor = encrypt(divisor, cc);
    time_t timer1;
    time_t timer2;
    time_t timer3;
    double seconds1, seconds2;
    time(&timer1);
    Ciphertext<DCRTPoly> cPubQuotient = intPubDivision(cDividend, divisor, cc);
    time(&timer2);
    seconds1 = difftime(timer2,timer1);
    std::vector<int64_t> result1 = decrypt(cPubQuotient, cc);
    std::cout << "\nPublic division result: " << result1[0] << std::endl;
    std::cout << "\nTime used to divide: " << seconds1 << " seconds "<< std::endl;
    Ciphertext<DCRTPoly> cPrivQuotient = intPrivDivision(cDividend, cDivisor, cc);
    time(&timer3);
    seconds2 = difftime(timer3,timer2);

    // -----------------------------------------------------

    // Here the result is sent to the client

    // -------------------- CLIENT SIDE --------------------

    std::vector<int64_t> result2 = decrypt(cPrivQuotient, cc);
    std::cout << "\nPrivate division result: " << result2[0] << std::endl;
    std::cout << "\nTime used to divide: " << seconds2 << " seconds "<< std::endl;
}

int main() {

    // std::string operation = intro();
    // while (operation != "q") {
    //     if (operation == "i") {
    //         intComparator();
    //     } else if (operation == "s") {
    //         stringComparator();
    //     } else {
    //         std::cout << "Please, introduce a valid value."<< std::endl;
    //     }
    //     operation = intro();
    // }
    intDivision();
}