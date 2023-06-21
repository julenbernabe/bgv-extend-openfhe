/**
 * @ Author: Julen Bernabe Rodriguez <julen.bernabe@tecnalia.com>
 * @ Create Time: 2023-06-14 11:50:19
 * @ Description: Copyright (c) 2023 Tecnalia Research & Innovation
 */

/*
 * Threshold division
 */

#include "scheme/bgvrns/cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>
#include <time.h>

interpolationPoints integerPositiveDivisionPoints(int divisor, int p) {
    interpolationPoints ip;
    for (int i = 0; i < p; i++) {
        ip.x.push_back(i);
        ip.fx.push_back(i / divisor);
    }
    return ip;
}

interpolationPoints integerDivisionPoints(int divisor, int p) {
    interpolationPoints ip;
    for (int i = 0; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(i / divisor);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(-(p-i) / divisor);
        }
        
    }
    return ip;
}

Ciphertext<DCRTPoly> intPubDivision(Ciphertext<DCRTPoly> dividend, int divisor, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    if (divisor != 0) {
        std::vector<Ciphertext<DCRTPoly>> dividendPowers = powers(dividend, cc);
        interpolationPoints ip = integerDivisionPoints(divisor, p);
        std::vector<int64_t> poly = getLagrangePoly(ip, p);
        std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
        Ciphertext<DCRTPoly> evaluation = evalInterpolator(dividendPowers, cPoly, cc);
        return evaluation;
    } else {
        Ciphertext<DCRTPoly> evaluation = encryptThresholdBGV(divisor, cc.pks[cc.lastKey], cc.cryptoContext);
        return evaluation; 
    }
}

Ciphertext<DCRTPoly> intPrivDivision(Ciphertext<DCRTPoly> dividend, Ciphertext<DCRTPoly> divisor, cryptoTools cc) {
    std::vector<Ciphertext<DCRTPoly>> dividendPowers = powers(dividend, cc);
    std::vector<Ciphertext<DCRTPoly>> divisorPowers = powers(divisor, cc);
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    Ciphertext<DCRTPoly> divResult = encryptThresholdBGV(0, cc.pks[cc.lastKey], cc.cryptoContext);
    for (int i = 1; i < p; i++) {
        Ciphertext<DCRTPoly> ci = encryptThresholdBGV(i, cc.pks[cc.lastKey], cc.cryptoContext);
        interpolationPoints ip = integerDivisionPoints(i, p);
        std::vector<int64_t> poly = getLagrangePoly(ip, p);
        std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
        Ciphertext<DCRTPoly> evaluation = evalInterpolator(dividendPowers, cPoly, cc);
        Ciphertext<DCRTPoly> equals = equal(ci, divisor, cc);
        Ciphertext<DCRTPoly> pre = cc.cryptoContext->EvalMult(evaluation, equals);
        divResult = cc.cryptoContext->EvalAdd(divResult, pre);
    }
    return divResult;
}


