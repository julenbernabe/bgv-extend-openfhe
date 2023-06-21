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

/** 
 * @brief Structure for storing X and Y sets from Step 1
 * 
 * @param x: array containing the elements of X
 * @param fx: array containing the elements of Y (the f(x)'s)
 */
struct Points {
    std::vector<int64_t> x;
    std::vector<int64_t> fx;
};

typedef struct Points interpolationPoints;
/**
 * @brief Compute the product between two polynomials mod p
 * 
 * @param px first polynomial
 * @param qx second polynomial
 * @param p prime number
 * @return std::vector<int64_t> containing coefficients of result
 */
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
/**
 * @brief Compute the addition of two polynomials mod p
 * 
 * @param px first polynomial
 * @param qx second polynomial
 * @param p prime number
 * @return std::vector<int64_t> containing coefficients of result
 */
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
/**
 * @brief Make coefficients of polynomial be mod p
 * 
 * @param px polynomial to be normalized
 * @param p prime number
 * @return std::vector<int64_t> containing the normalized coefficients
 */
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
/**
 * @brief Get the Lagrange Polynomial using Lagrange's Interpolation Formula
 * 
 * @param ip interpolation points (struct containing X and Y from Step 1)
 * @param p prime number
 * @return std::vector<int64_t> 
 */
std::vector<int64_t> getLagrangePoly(interpolationPoints ip, int p) {
    std::vector<int64_t> result;
    for (uint i = 0; i < ip.x.size(); i++) {///< initialize polynomial for the result
        result.push_back(0);
    }
    for (uint i = 0; i < ip.x.size(); i++) {///< loop for computing the summation
        std::vector<int64_t> roundResult = {1};
        int64_t denominator = 1;
        for (uint j = 0; j < ip.x.size(); j++) {///< loop for computing prod(x-xj)(xi-xj)
            if (i != j) {
                std::vector<int64_t> monomial = {-ip.x[j], 1};
                roundResult = polyProd(roundResult, monomial, p);
                denominator = (denominator * (ip.x[i] - ip.x[j])) % p;
            }
        }
        std::vector<int64_t> scalar = {inverse(denominator, p) * ip.fx[i]};///< compute inverse of prod(xi-xj)
        roundResult = polyProd(roundResult, scalar, p);
        result = polyAdd(roundResult, result, p);
    }
    return normalizePoly(result, p);
}
/**
 * @brief Encrypt the coefficients of the interpolation polynomial
 * 
 * @param poly polynomial to be encrypted
 * @param cc cryptographical context for the encryption
 * @return std::vector<Ciphertext<DCRTPoly>> array of ciphertexts with the encryption of each coefficient
 */
std::vector<Ciphertext<DCRTPoly>> encryptInterpolator(std::vector<int64_t> poly, cryptoTools cc) {
    std::vector<Ciphertext<DCRTPoly>> result;
    for (uint i = 0; i < poly.size(); i++){
        result.push_back(encryptThresholdBGV(poly[i], cc.pks[cc.lastKey], cc.cryptoContext));
    }
    return result;
}
/**
 * @brief Evaluate Lagrange's Polynomial for some ciphertext c
 * 
 * @param powers the powers of c (i.e. {c, c^2, ..., c^{p-1}})
 * @param polynomial Lagranges Interpolation Polynomial
 * @param cc cryptographical context
 * @return Ciphertext<DCRTPoly> ciphertext containing the result of the evaluation
 */
Ciphertext<DCRTPoly> evalInterpolator(std::vector<Ciphertext<DCRTPoly>> powers, std::vector<Ciphertext<DCRTPoly>> polynomial, cryptoTools cc) {
    Ciphertext<DCRTPoly> result = encryptThresholdBGV(0, cc.pks[cc.lastKey], cc.cryptoContext);
    result = cc.cryptoContext->EvalAdd(result, polynomial[0]);
    for (uint i = 0; i < powers.size(); i++) {
        Ciphertext<DCRTPoly> product = cc.cryptoContext->EvalMult(powers[i], polynomial[i+1]);
        result = cc.cryptoContext->EvalAdd(result, product);
    }
    return result;
}