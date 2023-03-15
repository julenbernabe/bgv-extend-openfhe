// Created on February 13 2023
// By Julen Bernabe Rodriguez <julen.bernabe@tecnalia.com>
// Copyright (c) 2023 Tecnalia Research & Innovation

/*
 * BGV basics
 */

#include "scheme/bgvrns/cryptocontext-bgvrns.h"
#include "gen-cryptocontext.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

using namespace lbcrypto;

struct Points {
    std::vector<int64_t> x;
    std::vector<int64_t> fx;
};

typedef struct Points interpolationPoints;

std::vector<int64_t> polyProd(std::vector<int64_t> px, std::vector<int64_t> qx, int p) {
   std::vector<int64_t> rx;
   int rsize = px.size() + qx.size() - 1;
   for (int i = 0; i < rsize; i++) {
        rx.push_back(0);
   }
   for (uint i = 0; i < px.size(); i++) {
      for (uint j = 0; j < qx.size(); j++) {
         rx[i + j] += px[i] * qx[j];
         rx[i + j] = rx[i + j] % p;
      }
   }
   return rx;
}

std::vector<int64_t> polyAdd(std::vector<int64_t> px, std::vector<int64_t> qx, int p) {
    std::vector<int64_t> rx;
    uint maxDegree = std::max(px.size(), qx.size());
    for (uint i = 0; i < maxDegree; i++) {
        rx.push_back(0);
        if (i < px.size()) {
            rx[i] = (rx[i] + px[i]) % p;
        }
        if (i < qx.size()) {
            rx[i] = (rx[i] + qx[i]) % p;
        }
    }
    return rx;
}

std::vector<int64_t> normalizePoly(std::vector<int64_t> px, int p) {
    std::vector<int64_t> rx;
    for (uint i = 0; i < px.size(); i++) {
        rx.push_back(0);
        if (px[i] < 0) {
            rx[i] = uint(p + px[i]);
        } else {
            rx[i] = uint(px[i]);
        }
    }
    return rx;
}

std::vector<int64_t> getLagrangePoly(interpolationPoints ip, int p) {
    std::vector<int64_t> result;
    for (uint i = 0; i < ip.x.size(); i++) {
        result.push_back(0);
    }
    for (uint i = 0; i < ip.x.size(); i++) {
        std::vector<int64_t> roundResult = {1};
        int64_t denominator = 1;
        for (uint j = 0; j < ip.x.size(); j++) {
            if (i != j) {
                std::vector<int64_t> monomial = {-ip.x[j], 1};
                roundResult = polyProd(roundResult, monomial, p);
                denominator = (denominator * (ip.x[i] - ip.x[j])) % p;
            }
        }
        std::vector<int64_t> scalar = {inverse(denominator, p) * ip.fx[i]};
        roundResult = polyProd(roundResult, scalar, p);
        result = polyAdd(roundResult, result, p);
    }
    return normalizePoly(result, p);
}

std::vector<Ciphertext<DCRTPoly>> encryptInterpolator(std::vector<int64_t> poly, cryptoTools cc) {
    std::vector<Ciphertext<DCRTPoly>> result;
    for (uint i = 0; i < poly.size(); i++){
        result.push_back(encrypt(poly[i], cc));
    }
    return result;
}

Ciphertext<DCRTPoly> evalInterpolator(std::vector<Ciphertext<DCRTPoly>> powers, std::vector<Ciphertext<DCRTPoly>> polynomial, cryptoTools cc) {
    Ciphertext<DCRTPoly> result = encrypt(0, cc);
    result = cc.cryptoContext->EvalAdd(result, polynomial[0]);
    for (uint i = 0; i < powers.size(); i++) {
        Ciphertext<DCRTPoly> product = cc.cryptoContext->EvalMult(powers[i], polynomial[i+1]);
        result = cc.cryptoContext->EvalAdd(result, product);
    }
    return result;
}

