#pragma once
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <gmp.h>
#include <stddef.h>

#define KEY_SIZE 128  // in bytes, adjust if needed

void encryptThenSign(mpz_t pvtKey, mpz_t pubKey, unsigned char* msg, size_t msgSize, unsigned char* outEncryptedAESKey, unsigned char* outCipherText, int* outCipherLen, unsigned char* outSignature, unsigned int* outSigLen);

int verifyAndDecrypt(unsigned char* encryptedAESKey, unsigned char* cipherText, int cipherTextLen, unsigned char* signature, unsigned int sigLen, unsigned char* outMsg);

int verifySig(mpz_t pubKey, unsigned char* msg, size_t msgSize,
              unsigned char* sign, size_t signSize);

void deriveSharedSecretPubKey(mpz_t selfSecretKey, mpz_t selfPubKey,
                               mpz_t otherPubKey,
                               unsigned char* sharedSecret, size_t keySize);

void generateMAC(unsigned char* key, unsigned char* msg, size_t msgSize,
                 unsigned char* mac);

int verifyMAC(unsigned char* key, unsigned char* msg, size_t msgSize,
              unsigned char* mac);

void handshakeProtocol(int sockfd, int isClient, unsigned char* sharedSecretOut);
              

#endif
