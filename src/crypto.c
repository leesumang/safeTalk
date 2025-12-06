// SafeTalk 암호 처리 모듈 (X25519 DH + AES-256-CBC)
#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#define AES_KEY_LEN 32
#define AES_IV_LEN 16
#define SHA256_LEN 32

// DH 키 생성
EVP_PKEY *generate_dh_keypair(void) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return NULL;

    if (EVP_PKEY_keygen_init(pctx) <= 0) return NULL;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) return NULL;

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

// 공유 비밀키 계산
unsigned char *derive_shared_secret(
    EVP_PKEY *my_key, EVP_PKEY *peer_key, size_t *secret_len
) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_derive_init(ctx) <= 0) return NULL;
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) return NULL;

    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) return NULL;

    unsigned char *secret = malloc(*secret_len);
    if (!secret) return NULL;

    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) {
        free(secret);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return secret;
}

// AES 키 도출
void derive_aes_key_from_secret(
    const unsigned char *secret, size_t len, unsigned char *out_key
) {
    unsigned char hash[SHA256_LEN];
    SHA256(secret, len, hash);
    memcpy(out_key, hash, AES_KEY_LEN);
}

// AES 암호화 
int aes_encrypt(
    const unsigned char *plaintext, int plaintext_len,
    const unsigned char *key, const unsigned char *iv,
    unsigned char *ciphertext
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int out_len, total = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, plaintext_len);
    total += out_len;

    EVP_EncryptFinal_ex(ctx, ciphertext + total, &out_len);
    total += out_len;

    EVP_CIPHER_CTX_free(ctx);
    return total;
}

// AES 복호화
int aes_decrypt(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *key, const unsigned char *iv,
    unsigned char *plaintext
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int out_len, total = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, ciphertext_len);
    total += out_len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total += out_len;

    EVP_CIPHER_CTX_free(ctx);
    return total;
}

// SHA-256
static void simple_sha256(const unsigned char *data, size_t len, unsigned char *out) {
    SHA256(data, len, out);
}

// 암호화 메시지 송신
int send_secure_message(int sock, unsigned char *aes_key, const char *plaintext) {
    unsigned char iv[AES_IV_LEN], ciphertext[4096], hash[SHA256_LEN];

    RAND_bytes(iv, AES_IV_LEN);

    int cipher_len = aes_encrypt(
        (unsigned char *)plaintext,
        strlen(plaintext),
        aes_key, iv, ciphertext
    );
    if (cipher_len <= 0) return -1;

    simple_sha256(ciphertext, cipher_len, hash);

    uint32_t total = AES_IV_LEN + cipher_len + SHA256_LEN;
    uint32_t net_total = htonl(total);

    write(sock, &net_total, 4);
    write(sock, iv, AES_IV_LEN);
    write(sock, ciphertext, cipher_len);
    write(sock, hash, SHA256_LEN);

    return 0;
}

// 암호화 메시지 수신
int recv_secure_message(int sock, unsigned char *aes_key, char *out_plain) {
    uint32_t net_total;
    if (read(sock, &net_total, 4) != 4) return -1;

    uint32_t total = ntohl(net_total);
    if (total < AES_IV_LEN + SHA256_LEN) return -1;

    int cipher_len = total - AES_IV_LEN - SHA256_LEN;

    unsigned char iv[AES_IV_LEN], ciphertext[4096];
    unsigned char hash_recv[SHA256_LEN], hash_calc[SHA256_LEN];

    if (read(sock, iv, AES_IV_LEN) != AES_IV_LEN) return -1;

    int remain = cipher_len, off = 0;
    while (remain > 0) {
        int n = read(sock, ciphertext + off, remain);
        if (n <= 0) return -1;
        remain -= n;
        off += n;
    }

    if (read(sock, hash_recv, SHA256_LEN) != SHA256_LEN) return -1;

    simple_sha256(ciphertext, cipher_len, hash_calc);
    if (memcmp(hash_calc, hash_recv, SHA256_LEN) != 0) return -1;

    int plain_len = aes_decrypt(ciphertext, cipher_len, aes_key, iv, (unsigned char *)out_plain);
    if (plain_len <= 0) return -1;

    out_plain[plain_len] = '\0';
    return plain_len;
}
