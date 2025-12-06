// SafeTalk 암호 모듈 헤더 (X25519 + AES-256-CBC)
#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <stddef.h>

// AES-256-CBC 암호화
int aes_encrypt(
    const unsigned char *plaintext,
    int plaintext_len,
    const unsigned char *key,      // 32 bytes
    const unsigned char *iv,       // 16 bytes
    unsigned char *ciphertext
);

// AES-256-CBC 복호화
int aes_decrypt(
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *plaintext
);

// X25519 DH 키쌍 생성
EVP_PKEY *generate_dh_keypair(void);

// 공유 비밀키 계산
unsigned char *derive_shared_secret(
    EVP_PKEY *my_key,
    EVP_PKEY *peer_key,
    size_t *secret_len
);

// 공유 비밀키 → AES-256 키(32바이트) 변환
void derive_aes_key_from_secret(
    const unsigned char *secret,
    size_t secret_len,
    unsigned char *out_key
);

// 암호화 메시지 송신
int send_secure_message(int sock, unsigned char *aes_key, const char *plaintext);

// 암호화 메시지 수신
int recv_secure_message(int sock, unsigned char *aes_key, char *out_plain);

#endif // CRYPTO_H
