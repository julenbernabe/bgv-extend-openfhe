/**
 * @ Author: Julen Bernabe Rodriguez <julen.bernabe@tecnalia.com>
 * @ Create Time: 2023-03-14 11:50:19
 * @ Description: Copyright (c) 2023 Tecnalia Research & Innovation
 */

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
#include "../lib/threshold/threshold-basics.cpp"
#include "../lib/threshold/threshold-power.cpp"
#include "../lib/threshold/threshold-interpolation.cpp"
#include "../lib/threshold/threshold-compare.cpp"
#include "../lib/threshold/threshold-int-division.cpp"

using namespace lbcrypto;

void threshold_divide() {
    

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

    std::cout << "\nTHRESHOLD BGV INTEGER DIVISIONS\n "<< std::endl;

    // -------------------- CLIENT SIDE --------------------

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

    Ciphertext<DCRTPoly> c3 = encryptThresholdBGV(dividend, cc.pks[cc.lastKey], cc.cryptoContext);

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
    Ciphertext<DCRTPoly> c4 = encryptThresholdBGV(divisor, cc.pks[cc.lastKey], cc.cryptoContext);

    time_t timer1;
    time_t timer2;
    time_t timer3;
    double seconds1, seconds2;
    time(&timer1);
    // Division by clear divisor (known by server)
    Ciphertext<DCRTPoly> cPubQuotient = intPubDivision(c3, divisor, cc);
    time(&timer2);
    seconds1 = difftime(timer2,timer1);
    // Division by encrypted divisor (unknown by server)
    Ciphertext<DCRTPoly> cPrivQuotient = intPrivDivision(c3, c4, cc);
    time(&timer3);
    seconds2 = difftime(timer3,timer2);

    // -------------------- DECRYPTION PROTOCOL --------------------

    // Public division
    std::vector<Ciphertext<DCRTPoly>> partialResultsPubQuotient = partialDecryptBGVLead(cPubQuotient, cc.sks[0], cc.cryptoContext);
    partialResultsPubQuotient = partialDecryptBGVMain(cPubQuotient, cc.sks[1], cc.cryptoContext, partialResultsPubQuotient);
    std::vector<int64_t> rPubQuotient = decryptThresholdBGV(partialResultsPubQuotient, cc.cryptoContext);
    // Private division
    std::vector<Ciphertext<DCRTPoly>> partialResultsPrivQuotient = partialDecryptBGVLead(cPrivQuotient, cc.sks[0], cc.cryptoContext);
    partialResultsPrivQuotient = partialDecryptBGVMain(cPrivQuotient, cc.sks[1], cc.cryptoContext, partialResultsPrivQuotient);
    std::vector<int64_t> rPrivQuotient = decryptThresholdBGV(partialResultsPrivQuotient, cc.cryptoContext);
    std::cout << "\nPublic division result: " << rPubQuotient[0] << std::endl;
    std::cout << "\nTime used to divide: " << seconds1 << " seconds "<< std::endl;
    std::cout << "\nPrivate division result: " << rPrivQuotient[0] << std::endl;
    std::cout << "\nTime used to divide: " << seconds2 << " seconds "<< std::endl;
}

int main() {
    threshold_divide();
}