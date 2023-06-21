/**
 * @ Author: Julen Bernabe Rodriguez <julen.bernabe@tecnalia.com>
 * @ Create Time: 2023-03-14 11:50:19
 * @ Description: Copyright (c) 2023 Tecnalia Research & Innovation
 */

/*
 * Threshold main comparisons program
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
#include "../lib/threshold/threshold-basics.cpp"
#include "../lib/threshold/threshold-power.cpp"
#include "../lib/threshold/threshold-interpolation.cpp"
#include "../lib/threshold/threshold-compare.cpp"

using namespace lbcrypto;

void threshold_compare() {
    

    cryptoTools cc = genThresholdBGVCryptoTools(257, 16);

    thresholdTools tt = init(cc.sks[0], cc.cryptoContext);

    // Now thresholdTools is sent to party B

    // party B generates her multi-party key (appended at the end of keys in cryptoTools)
    cc = newMultiPartyKey(cc);

    // then uses this multi-party key to update threshold keys
    tt.AddedKey = updateAddedMultKey(tt.AddedKey, cc.sks[1], cc.pks[1], cc.cryptoContext);

    // Now thresholdTools is sent again to party A to update MultKey

    // party A initializes the final mult key version (using added mult key)
    tt.MultKey = initFinalMultKey(tt.AddedKey, cc.sks[0], cc.pks[0], cc.cryptoContext);
    
    // Now thresholdTools is sent back to party B to update MultKey
    tt.MultKey = updateFinalMultKey(tt.AddedKey, tt.MultKey, cc.sks[1], cc.pks[1], cc.cryptoContext);

    // Now set final MultKey
    cc.cryptoContext = setFinalMultKey(tt.MultKey, cc.cryptoContext);

    std::cout << "\nTHRESHOLD BGV NON-LINEAR OPERATIONS\n "<< std::endl;

    // -------------------- CLIENT SIDE --------------------

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

    Ciphertext<DCRTPoly> c3 = encryptThresholdBGV(first, cc.pks[cc.lastKey], cc.cryptoContext);
    Ciphertext<DCRTPoly> c4 = encryptThresholdBGV(second, cc.pks[cc.lastKey], cc.cryptoContext);

    // -----------------------------------------------------

    // Here the ciphertexts are sent to the server

    // -------------------- SERVER SIDE --------------------
    time_t timer3;
    time_t timer4;
    double seconds1;
    time(&timer3);
    Ciphertext<DCRTPoly> cEq = equal(c3, c4, cc);
    Ciphertext<DCRTPoly> cGreater = gt(c3, c4, cc);
    Ciphertext<DCRTPoly> cGreaterEq = gteq(c3, c4, cc);
    Ciphertext<DCRTPoly> cLower = lt(c3, c4, cc);
    Ciphertext<DCRTPoly> cLowerEq = lteq(c3, c4, cc);
    Ciphertext<DCRTPoly> cMax = max(c3, c4, cc);
    Ciphertext<DCRTPoly> cMin = min(c3, c4, cc);
    time(&timer4);
    seconds1 = difftime(timer4,timer3);

    // -----------------------------------------------------

    // Here the result is sent to the client

    // -------------------- CLIENT SIDE --------------------

    // Decryption of equality test
    std::vector<Ciphertext<DCRTPoly>> partialResultsEq = partialDecryptBGVLead(cEq, cc.sks[0], cc.cryptoContext);
    partialResultsEq = partialDecryptBGVMain(cEq, cc.sks[1], cc.cryptoContext, partialResultsEq);
    std::vector<int64_t> rEq = decryptThresholdBGV(partialResultsEq, cc.cryptoContext);
    // Decryption of greater test
    std::vector<Ciphertext<DCRTPoly>> partialResultsGreater = partialDecryptBGVLead(cGreater, cc.sks[0], cc.cryptoContext);
    partialResultsGreater = partialDecryptBGVMain(cGreater, cc.sks[1], cc.cryptoContext, partialResultsGreater);
    std::vector<int64_t> rGreater = decryptThresholdBGV(partialResultsGreater, cc.cryptoContext);
    // Decryption of greater or equal test
    std::vector<Ciphertext<DCRTPoly>> partialResultsGreaterEq = partialDecryptBGVLead(cGreaterEq, cc.sks[0], cc.cryptoContext);
    partialResultsGreaterEq = partialDecryptBGVMain(cGreaterEq, cc.sks[1], cc.cryptoContext, partialResultsGreaterEq);
    std::vector<int64_t> rGreaterEq = decryptThresholdBGV(partialResultsGreaterEq, cc.cryptoContext);
    // Decryption of lower test
    std::vector<Ciphertext<DCRTPoly>> partialResultsLower = partialDecryptBGVLead(cLower, cc.sks[0], cc.cryptoContext);
    partialResultsLower = partialDecryptBGVMain(cLower, cc.sks[1], cc.cryptoContext, partialResultsLower);
    std::vector<int64_t> rLower = decryptThresholdBGV(partialResultsLower, cc.cryptoContext);
    // Decryption of lower or equal test
    std::vector<Ciphertext<DCRTPoly>> partialResultsLowerEq = partialDecryptBGVLead(cLowerEq, cc.sks[0], cc.cryptoContext);
    partialResultsLowerEq = partialDecryptBGVMain(cLowerEq, cc.sks[1], cc.cryptoContext, partialResultsLowerEq);
    std::vector<int64_t> rLowerEq = decryptThresholdBGV(partialResultsLowerEq, cc.cryptoContext);
    // Decryption of min(c3, c4)
    std::vector<Ciphertext<DCRTPoly>> partialResultsMin = partialDecryptBGVLead(cMin, cc.sks[0], cc.cryptoContext);
    partialResultsMin = partialDecryptBGVMain(cMin, cc.sks[1], cc.cryptoContext, partialResultsMin);
    std::vector<int64_t> rMin = decryptThresholdBGV(partialResultsMin, cc.cryptoContext);
    // Decryption of max(c3, c4)
    std::vector<Ciphertext<DCRTPoly>> partialResultsMax = partialDecryptBGVLead(cMax, cc.sks[0], cc.cryptoContext);
    partialResultsMax = partialDecryptBGVMain(cMax, cc.sks[1], cc.cryptoContext, partialResultsMax);
    std::vector<int64_t> rMax = decryptThresholdBGV(partialResultsMax, cc.cryptoContext);
    std::cout << first << " == " << second << ": " << rEq[0] << std::endl;
    std::cout << first << " > " << second << ": " << rGreater[0] << std::endl;
    std::cout << first << " >= " << second << ": " << rGreaterEq[0] << std::endl;
    std::cout << first << " < " << second << ": " << rLower[0] << std::endl;
    std::cout << first << " <= " << second << ": " << rLowerEq[0] << std::endl;
    std::cout << "max(" << first << ", " <<  second << ") = " << rMax[0] << std::endl;
    std::cout << "min(" << first << ", " <<  second << ") = " << rMin[0] << std::endl;
    std::cout << "\nTime used to compare: " << seconds1 << " seconds "<< std::endl;
}

int main() {
    threshold_compare();
}