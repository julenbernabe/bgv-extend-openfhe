/**
 * @ Author: Julen Bernabe Rodriguez <julen.bernabe@tecnalia.com>
 * @ Create Time: 2023-06-14 11:50:19
 * @ Description: Copyright (c) 2023 Tecnalia Research & Innovation
 */

/*
 * Threshold basics
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
 * @brief crypto contains all the cryptographical information used in threshold decryption
 * 
 * @param cryptoContext contains the parameters definings the BGV encryption (n, p, q...)
 * @param pks contains the list of public keys forming pk*
 * @param sks contains the list of secret keys forming sk* (only used for decryption)
 * @param lastKey contains the index of the last public key, for players to be able to use it during encryption
 */
struct crypto {
    CryptoContext<DCRTPoly> cryptoContext;
    std::vector<PublicKey<DCRTPoly>> pks;
    std::vector<PrivateKey<DCRTPoly>> sks;
    uint lastKey;
};

/**
 * @brief threshold contains the evaluation key
 * 
 * @param AddedKey contains the partial evaluation key encapsulating (sk1+...+skn)
 * @param MultKey contains the evaluation key
 */
struct threshold {
    EvalKey<DCRTPoly> AddedKey;
    EvalKey<DCRTPoly> MultKey;
};

typedef struct crypto cryptoTools;
typedef struct threshold thresholdTools;

/**
 * @brief generate the cryptographical context for threshold BGV using the security parameters
 * 
 * @param ptm plaintext modulus
 * @param multDepth max number of products that we want to compute over the same ciphertext
 * @param level ring dimension
 * @return CryptoContext<DCRTPoly> cryptographical context
 */
CryptoContext<DCRTPoly> GenerateThresholdBGVrnsContext(usint ptm, usint multDepth, usint level) {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(ptm);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);
    parameters.SetRingDim(level);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingTechnique(FIXEDAUTO);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    return cc;
}

/**
 * @brief generate cryptoTools (cryptographical context + public keys + secret keys)
 * 
 * @param p plaintext modulus
 * @param level ring dimension
 * @return cryptoTools (cryptographical context + public keys + secret keys)
 */
cryptoTools genThresholdBGVCryptoTools(usint p, usint level) {
    cryptoTools cc;

    // compute binary representation of p-1
    std::vector<uint> binaryRep = binaryRepresentationOfExp(p-1);
    
    // Define parameters of BGV cryptographic context
    usint ptm                  = p;
    usint depth                = binaryRep.size() + 1;      // Maximum depth needed is the binary representation of p-1

    // Generate context with above parameters
    cc.cryptoContext = GenerateThresholdBGVrnsContext(ptm, depth, level);

    // Key generation
    KeyPair<DCRTPoly> keys = cc.cryptoContext->KeyGen();
    cc.pks.push_back(keys.publicKey);
    cc.sks.push_back(keys.secretKey);
    cc.lastKey = 0;
    return cc;
}

/**
 * @brief generate ck encapsulating sk_k for Pk
 * 
 * @param sk secret key sk1
 * @param cc cryptographical context
 * @return thresholdTools 
 */
thresholdTools init(PrivateKey<DCRTPoly> sk, CryptoContext<DCRTPoly> cc) {
    thresholdTools tt;

    // Generate c11 encapsulating sk1 for P1
    tt.AddedKey = cc->KeySwitchGen(sk, sk);

    return tt;
}

/**
 * @brief generate pk* derived from a previous threshold pk' and the pk_k for player Pk (i.e. pk* = pk_k + pk')
 * 
 * Observation: If every player Pk calls this function, the last player would obtain pk*
 * 
 * @param cc cryptographical context
 * @return cryptoTools 
 */
cryptoTools newMultiPartyKey(cryptoTools cc) {
    // MultiPartyKeyGen generates a key pair (sk_k, pk*) where pk* is the shared public key for k players 
    KeyPair<DCRTPoly> keyPair2 = cc.cryptoContext->MultipartyKeyGen(cc.pks[cc.lastKey]);
    // Add pk* at the end of list of public keys in cryptoTools
    cc.pks.push_back(keyPair2.publicKey);
    // Add sk_k at the end of list of secret keys in cryptoTools
    cc.sks.push_back(keyPair2.secretKey);
    // Update last key index
    cc.lastKey += 1;
    return cc;
}

/**
 * @brief compute Ck encapsulating (sk_k + sk*) for player Pk
 * 
 * @param previousKey sk* = sk_1 + ... + sk_{k-1}
 * @param sk sk_k
 * @param pk pk*
 * @param cc cryptographical context
 * @return EvalKey<DCRTPoly> ek*
 */
EvalKey<DCRTPoly> updateAddedMultKey(EvalKey<DCRTPoly> previousKey, PrivateKey<DCRTPoly> sk, PublicKey<DCRTPoly> pk, CryptoContext<DCRTPoly> cc) {
    // Generate ck encapsulating sk_k for Pk (similar to function init() but considering previous evalkey C_{k-1}=c1+...+c{k-1})
    auto newKey = cc->MultiKeySwitchGen(sk, sk, previousKey);
    // Compute Ck = ck + C_{k-1}
    return cc->MultiAddEvalKeys(previousKey, newKey, pk->GetKeyTag());
}

/**
 * @brief compute ^C1 = sk x C + z
 * 
 * @param addedKey is C = c1 + ... + cn
 * @param sk is sk_k
 * @param pk is pk*
 * @param cc cryptographical context
 * @return EvalKey<DCRTPoly> is ^C1
 */
EvalKey<DCRTPoly> initFinalMultKey(EvalKey<DCRTPoly> addedKey, PrivateKey<DCRTPoly> sk, PublicKey<DCRTPoly> pk, CryptoContext<DCRTPoly> cc) {
    // compute ^C1
    return cc->MultiMultEvalKey(sk, addedKey, pk->GetKeyTag());
}

/**
 * @brief compute ^Ck = (sk x C + z) + ^C
 * 
 * @param addedKey is C = c1 + ... + cn
 * @param previousKey is ^C = ^C1 + ^C{k-1}
 * @param sk is sk_k
 * @param pk is pk*
 * @param cc cryptographical context
 * @return EvalKey<DCRTPoly> is ^Ck
 */
EvalKey<DCRTPoly> updateFinalMultKey(EvalKey<DCRTPoly> addedKey, EvalKey<DCRTPoly> previousKey, PrivateKey<DCRTPoly> sk, PublicKey<DCRTPoly> pk, CryptoContext<DCRTPoly> cc) {
    // compute c' = (sk x C + z)
    auto newKey = cc->MultiMultEvalKey(sk, addedKey, pk->GetKeyTag());
    // Compute ^Ck = c' + ^C
    return cc->MultiAddEvalMultKeys(newKey, previousKey, newKey->GetKeyTag());
}

/**
 * @brief set ^C = ^C1 + ... + ^Cn as the evalKey in cryptographical context
 * 
 * @param finalMultKey is ^C
 * @param cc cryptographical context
 * @return CryptoContext<DCRTPoly> the new cryptographical context has evalKey inserted
 */
CryptoContext<DCRTPoly> setFinalMultKey(EvalKey<DCRTPoly> finalMultKey, CryptoContext<DCRTPoly> cc) {
    cc->InsertEvalMultKey({finalMultKey});
    return cc;
}

/**
 * @brief encrypt integer using threshold cryptographical context
 * 
 * @param n integer to be encrypted
 * @param pk threshold public key
 * @param cc cryptographical context
 * @return Ciphertext<DCRTPoly> ciphertext encrypting n
 */
Ciphertext<DCRTPoly> encryptThresholdBGV(int n, PublicKey<DCRTPoly> pk, CryptoContext<DCRTPoly> cc) {
    // Generate vector with the integer
    std::vector<int64_t> vectorOfInts = {n};

    // Encode vector as plaintext
    Plaintext plaintext               = cc->MakePackedPlaintext(vectorOfInts);

    // Encrypt plaintext
    Ciphertext<DCRTPoly> ciphertext   = cc->Encrypt(pk, plaintext);
    return ciphertext;
}

/**
 * @brief compute partial decryption of ciphertext for player P1 using sk_1
 * 
 * @param c ciphertext to be decrypted
 * @param sk partial secret key
 * @param cc cryptographical context
 * @return std::vector<Ciphertext<DCRTPoly>> containing only one element: this partial decryption
 */
std::vector<Ciphertext<DCRTPoly>> partialDecryptBGVLead(Ciphertext<DCRTPoly> c, PrivateKey<DCRTPoly> sk, CryptoContext<DCRTPoly> cc) {
    // Initialize plaintext for result
    Plaintext partialPlaintextResult;
    // compute w1, the partial decryption of c using sk1
    auto ciphertextPartial = cc->MultipartyDecryptLead({c}, sk);
    // initialize array to store future partial decryptions
    std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    // add w1 to the previous array
    partialCiphertextVec.push_back(ciphertextPartial[0]);
    return partialCiphertextVec;
}

/**
 * @brief compute partial decryption of ciphertext for player Pk using sk_k
 * 
 * @param c ciphertext to be decrypted
 * @param sk is sk_k
 * @param cc cryptographical context
 * @param partialCiphertextVec vector containing previous partial decryptions {w1, ..., w{k-1}}
 * @return std::vector<Ciphertext<DCRTPoly>> vector containing {w1, ..., wk}
 */
std::vector<Ciphertext<DCRTPoly>> partialDecryptBGVMain(Ciphertext<DCRTPoly> c, PrivateKey<DCRTPoly> sk, CryptoContext<DCRTPoly> cc, std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec) {
    // Initialize plaintext for result
    Plaintext partialPlaintextResult;
    // compute wk using sk_k
    auto ciphertextPartial = cc->MultipartyDecryptMain({c}, sk);
    // add wk at the end of partialCiphertextVec
    partialCiphertextVec.push_back(ciphertextPartial[0]);
    return partialCiphertextVec;
}

/**
 * @brief compute final decryption using all partial decryptions
 * 
 * @param partialCiphertextVec array containing all partal decryptions {w1, ..., wn}
 * @param cc cryptographical context
 * @return std::vector<int64_t> containing the result
 */
std::vector<int64_t> decryptThresholdBGV(std::vector<Ciphertext<DCRTPoly>> partialCiphertextVec, CryptoContext<DCRTPoly> cc) {
    // Initialize plaintext for result
    Plaintext plaintextResult;
    // compute c + w1 + ... + wn to finally decrypt ciphertext
    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextResult);
    // decode plaintext to obtain message (as vector of coefficients)
    std::vector<int64_t> result = plaintextResult->GetPackedValue();
    return result;
}