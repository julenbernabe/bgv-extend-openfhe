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
#include "../lib/lib.cpp"
#include "../lib/bgv/bgv-basics.cpp"
#include "../lib/bgv/bgv-power.cpp"
#include "../lib/bgv/bgv-interpolation.cpp"
#include "../lib/bgv/bgv-compare.cpp"

using namespace lbcrypto;


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
        std::cout << "\nInteger must be between " << -(p - 1) / 4 << " and " << (p - 1) / 4 << std::endl;
        std::cout << "First integer: ";
        std::cin >> first;
    }
    while (first < -(p-1)/2) {
        std::cout << "\nInteger must be between " << -(p - 1) / 4 << " and " << (p - 1) / 4 << std::endl;
        std::cout << "First integer: ";
        std::cin >> first;
    }
    std::cout << "\t - Second integer: ";
    std::cin >> second;
    while (second > (p-1)/2) {
        std::cout << "\nInteger must be between " << -(p - 1) / 4 << " and " << (p - 1) / 4 << std::endl;
        std::cout << "Second integer: ";
        std::cin >> second;
    }
    while (second < -(p-1)/2) {
        std::cout << "\nInteger must be between " << -(p - 1) / 4 << " and " << (p - 1) / 4 << std::endl;
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
        } else if (operation == "S") {
            getSign();
        } else {
            std::cout << "Please, introduce a valid value."<< std::endl;
        }
        operation = intro();
    }
}