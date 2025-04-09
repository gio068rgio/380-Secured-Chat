#include "dh.h"
#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include "handshake.h"

#define KEY_SIZE 128

void generateEphemeralKeyPair(mpz_t secretKey, mpz_t pubKey) {
    dhGen(secretKey, pubKey);
}

void deriveSharedSecretPubKey(mpz_t selfSecretKey, mpz_t selfPubKey, mpz_t otherPubKey, unsigned char* sharedSecret, size_t keySize) {
    dhFinal(selfSecretKey, selfPubKey, otherPubKey, sharedSecret, keySize);
}

void encryptThenSign(mpz_t pvtKey, mpz_t pubKey, unsigned char* msg, size_t msgSize, unsigned char* outEncryptedAESKey, unsigned char* outCipherText, int* outCipherLen, unsigned char* outSignature, unsigned int* outSigLen) {
    FILE *rsaPubFile = fopen("receiver_public.pem", "r");
    FILE *rsaPrivFile = fopen("sender_private.pem", "r");
    RSA *rsaPub = PEM_read_RSA_PUBKEY(rsaPubFile, NULL, NULL, NULL);
    RSA *rsaPriv = PEM_read_RSAPrivateKey(rsaPrivFile, NULL, NULL, NULL);
    fclose(rsaPubFile); fclose(rsaPrivFile);

    unsigned char aesKey[32];
    unsigned char iv[16];
    RAND_bytes(aesKey, sizeof(aesKey));
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ciphertextLen = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, iv);
    EVP_EncryptUpdate(ctx, outCipherText, &len, msg, msgSize);
    ciphertextLen = len;
    EVP_EncryptFinal_ex(ctx, outCipherText + len, &len);
    ciphertextLen += len;
    *outCipherLen = ciphertextLen;
    EVP_CIPHER_CTX_free(ctx);

    RSA_public_encrypt(sizeof(aesKey), aesKey, outEncryptedAESKey, rsaPub, RSA_PKCS1_OAEP_PADDING);
    RSA_sign(NID_sha256, outCipherText, ciphertextLen, outSignature, outSigLen, rsaPriv);

    RSA_free(rsaPub);
    RSA_free(rsaPriv);
}

void generateMAC(unsigned char* key, unsigned char* msg, size_t msgSize, unsigned char* mac) {
    unsigned int macLen;
    HMAC(EVP_sha256(), key, KEY_SIZE, msg, msgSize, mac, &macLen);
}

int verifyMAC(unsigned char* key, unsigned char* msg, size_t msgSize, unsigned char* mac) {
    unsigned char expectedMac[EVP_MAX_MD_SIZE];
    unsigned int macLen;

    HMAC(EVP_sha256(), key, KEY_SIZE, msg, msgSize, expectedMac, &macLen);

    
    return CRYPTO_memcmp(mac, expectedMac, macLen) == 0;
}


int verifyAndDecrypt(unsigned char* encryptedAESKey, unsigned char* cipherText, int cipherTextLen, unsigned char* signature, unsigned int sigLen, unsigned char* outMsg) {
    FILE *rsaPrivFile = fopen("receiver_private.pem", "r");
    FILE *rsaPubFile = fopen("sender_public.pem", "r");
    RSA *rsaPriv = PEM_read_RSAPrivateKey(rsaPrivFile, NULL, NULL, NULL);
    RSA *rsaPub = PEM_read_RSA_PUBKEY(rsaPubFile, NULL, NULL, NULL);
    fclose(rsaPrivFile); fclose(rsaPubFile);

    unsigned char aesKey[32];
    RSA_private_decrypt(256, encryptedAESKey, aesKey, rsaPriv, RSA_PKCS1_OAEP_PADDING);

    int verified = RSA_verify(NID_sha256, cipherText, cipherTextLen, signature, sigLen, rsaPub);
    if (!verified) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plaintextLen = 0;
    unsigned char iv[16] = {0};
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, iv);
    EVP_DecryptUpdate(ctx, outMsg, &len, cipherText, cipherTextLen);
    plaintextLen = len;
    EVP_DecryptFinal_ex(ctx, outMsg + len, &len);
    plaintextLen += len;
    outMsg[plaintextLen] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    RSA_free(rsaPriv);
    RSA_free(rsaPub);
    return 1;
}

void handshakeProtocol() {
    mpz_t aliceSecretKey, alicePubKey;
    mpz_init(aliceSecretKey);
    mpz_init(alicePubKey);
    generateEphemeralKeyPair(aliceSecretKey, alicePubKey);

    mpz_t bobSecretKey, bobPubKey;
    mpz_init(bobSecretKey);
    mpz_init(bobPubKey);
    generateEphemeralKeyPair(bobSecretKey, bobPubKey);

    unsigned char aliceSharedSecret[KEY_SIZE];
    unsigned char bobSharedSecret[KEY_SIZE];

    deriveSharedSecretPubKey(aliceSecretKey, alicePubKey, bobPubKey, aliceSharedSecret, KEY_SIZE);
    deriveSharedSecretPubKey(bobSecretKey, bobPubKey, alicePubKey, bobSharedSecret, KEY_SIZE);

    if (memcmp(aliceSharedSecret, bobSharedSecret, KEY_SIZE) != 0) {
        printf("Key exchange failed!\n");
        return;
    }

    printf("Shared secrets match! Proceeding with secure message...\n");

    // Alice wants to send this message to Bob
    const char* plaintext = "Hello Bob, this is Alice!";
    size_t plaintextLen = strlen(plaintext);

    // Buffers
    unsigned char encryptedAESKey[256];
    unsigned char ciphertext[1024];
    unsigned char signature[256];
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned char decrypted[1024];

    int cipherLen = 0;
    unsigned int sigLen = 0;

    
    encryptThenSign(aliceSecretKey, alicePubKey,
                    (unsigned char*)plaintext, plaintextLen,
                    encryptedAESKey, ciphertext, &cipherLen,
                    signature, &sigLen);

    
    generateMAC(aliceSharedSecret, ciphertext, cipherLen, mac);

   

    printf("Alice sent encrypted message with HMAC and signature.\n");

   
    if (!verifyMAC(bobSharedSecret, ciphertext, cipherLen, mac)) {
        printf("MAC verification failed. Message may have been tampered with!\n");
        mpz_clears(aliceSecretKey, alicePubKey, bobSecretKey, bobPubKey, NULL);
        return;
    }

    printf("MAC verified successfully!\n");

    
    if (!verifyAndDecrypt(encryptedAESKey, ciphertext, cipherLen, signature, sigLen, decrypted)) {
        printf("Decryption or signature verification failed!\n");
        mpz_clears(aliceSecretKey, alicePubKey, bobSecretKey, bobPubKey, NULL);
        return;
    }

    printf("Decrypted message: %s\n", decrypted);

  
    mpz_clears(aliceSecretKey, alicePubKey, bobSecretKey, bobPubKey, NULL);
}
