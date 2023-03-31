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


interpolationPoints evalSignPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(0);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(1);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(-1);
        }  
    }
    return ip;
}

interpolationPoints evalEqualPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(1);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(0);
        } else if (i > (p-1)/2) {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(0);
        }
    }
    return ip;
}

interpolationPoints evalGreaterPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(0);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(1);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(0);
        }  
    }
    return ip;
}

interpolationPoints evalGreaterEqualPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(1);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(1);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(0);
        }  
    }
    return ip;
}

interpolationPoints evalLowerPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(0);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(0);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(1);
        }  
    }
    return ip;
}

interpolationPoints evalLowerEqualPoints(int p) {
    interpolationPoints ip;
    ip.x.push_back(0);
    ip.fx.push_back(1);
    for (int i = 1; i < p; i++) {
        if (i <= (p-1)/2) {
            ip.x.push_back(i);
            ip.fx.push_back(0);
        } else {
            ip.x.push_back(-(p-i));
            ip.fx.push_back(1);
        }  
    }
    return ip;
}

Ciphertext<DCRTPoly> sign(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalSignPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> equalZero(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalEqualPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> greaterThanZero(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalGreaterPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> greaterEqualThanZero(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalGreaterEqualPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> lowerThanZero(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalLowerPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> lowerEqualThanZero(Ciphertext<DCRTPoly> c, cryptoTools cc) {
    int p = cc.cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    std::vector<Ciphertext<DCRTPoly>> cPowers = powers(c, cc);
    interpolationPoints ip = evalLowerEqualPoints(p);
    std::vector<int64_t> poly = getLagrangePoly(ip, p);
    std::vector<Ciphertext<DCRTPoly>> cPoly = encryptInterpolator(poly, cc);
    Ciphertext<DCRTPoly> evaluation = evalInterpolator(cPowers, cPoly, cc);
    return evaluation;
}

Ciphertext<DCRTPoly> equal(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute difference = c1 - c2
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);
    
    Ciphertext<DCRTPoly> result = equalZero(difference, cc);

    return result;
}

Ciphertext<DCRTPoly> gt(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute the difference
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);

    // Check if it is greater than 0 or not
    Ciphertext<DCRTPoly> result = greaterThanZero(difference, cc);

    return result;
}

Ciphertext<DCRTPoly> gteq(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute the difference
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);

    // Check if it is greater than 0 or not
    Ciphertext<DCRTPoly> result = greaterEqualThanZero(difference, cc);

    return result;
}

Ciphertext<DCRTPoly> lt(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute the difference
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);

    // Check if it is greater than 0 or not
    Ciphertext<DCRTPoly> result = lowerThanZero(difference, cc);

    return result;
}

Ciphertext<DCRTPoly> lteq(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute the difference
    Ciphertext<DCRTPoly> difference = cc.cryptoContext->EvalSub(c1, c2);

    // Check if it is greater than 0 or not
    Ciphertext<DCRTPoly> result = lowerEqualThanZero(difference, cc);

    return result;
}

Ciphertext<DCRTPoly> max(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute d1 = c1 - c2
    Ciphertext<DCRTPoly> d1 = cc.cryptoContext->EvalSub(c1, c2);

    // Check if d1 is greater than 0 or not
    Ciphertext<DCRTPoly> g1 = greaterEqualThanZero(d1, cc);

    // Compute d2 = c2 - c1
    Ciphertext<DCRTPoly> d2 = cc.cryptoContext->EvalSub(c2, c1);

    // Check if d2 is greater than 0 or not
    Ciphertext<DCRTPoly> g2 = greaterThanZero(d2, cc);

    // Formula = g1 x c1 + g2 x c2
    Ciphertext<DCRTPoly> r1 = cc.cryptoContext->EvalMult(g1, c1);
    Ciphertext<DCRTPoly> r2 = cc.cryptoContext->EvalMult(g2, c2);
    Ciphertext<DCRTPoly> result = cc.cryptoContext->EvalAdd(r1, r2);
    return result;
}

Ciphertext<DCRTPoly> min(Ciphertext<DCRTPoly> c1, Ciphertext<DCRTPoly> c2, cryptoTools cc) {
    // Compute d1 = c1 - c2
    Ciphertext<DCRTPoly> d1 = cc.cryptoContext->EvalSub(c1, c2);

    // Check if d1 is greater than 0 or not
    Ciphertext<DCRTPoly> g1 = lowerEqualThanZero(d1, cc);

    // Compute d2 = c2 - c1
    Ciphertext<DCRTPoly> d2 = cc.cryptoContext->EvalSub(c2, c1);

    // Check if d2 is greater than 0 or not
    Ciphertext<DCRTPoly> g2 = lowerThanZero(d2, cc);

    // Formula = g1 x c1 + g2 x c2
    Ciphertext<DCRTPoly> r1 = cc.cryptoContext->EvalMult(g1, c1);
    Ciphertext<DCRTPoly> r2 = cc.cryptoContext->EvalMult(g2, c2);
    Ciphertext<DCRTPoly> result = cc.cryptoContext->EvalAdd(r1, r2);
    return result;
}