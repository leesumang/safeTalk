// SafeTalk - 1:1 암호화 메신저 서버
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/evp.h>
#include "crypto.h"

#define MAX_CLIENTS 2
#define BUF_SIZE 4096

typedef struct {
    int sock;
    char nickname[32];
    EVP_PKEY *dh_pubkey;
} ClientInfo;

ClientInfo clients[MAX_CLIENTS];
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_keys_exchanged = 0;

int other_index(int idx) { return idx == 0 ? 1 : 0; }

// 공개키 교환
void exchange_keys() {
    // 각 클라이언트의 공개키를 서로에게 그대로 릴레이
    if (!clients[0].dh_pubkey || !clients[1].dh_pubkey) {
        printf("[server] 공개키 준비 안 됨 (NULL)\n");
        return;
    }

    unsigned char pub0[200], pub1[200];
    size_t len0 = sizeof(pub0), len1 = sizeof(pub1);

    if (EVP_PKEY_get_raw_public_key(clients[0].dh_pubkey, pub0, &len0) <= 0) {
        printf("[server] client0 공개키 오류\n");
        return;
    }
    if (EVP_PKEY_get_raw_public_key(clients[1].dh_pubkey, pub1, &len1) <= 0) {
        printf("[server] client1 공개키 오류\n");
        return;
    }

    write(clients[1].sock, &len0, sizeof(len0));
    write(clients[1].sock, pub0, len0);

    write(clients[0].sock, &len1, sizeof(len1));
    write(clients[0].sock, pub1, len1);
}

// 클라이언트 처리
void *client_thread(void *arg) {
    int idx = *(int *)arg;
    free(arg);

    int sock = clients[idx].sock;
    char buf[BUF_SIZE];

    // 1) 닉네임 + 공개키 수신
    if (read(sock, clients[idx].nickname, sizeof(clients[idx].nickname)) <= 0) {
        clients[idx].sock = -1;
        close(sock);
        return NULL;
    }

    size_t pub_len;
    if (read(sock, &pub_len, sizeof(pub_len)) <= 0) return NULL;

    unsigned char pub_buf[200];
    if (read(sock, pub_buf, pub_len) <= 0) return NULL;

    clients[idx].dh_pubkey =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub_buf, pub_len);

    // 2) 두 명이 모두 연결되면 공개키를 상호 전송 (한 번만)
    pthread_mutex_lock(&g_mutex);
    if (clients[0].sock > 0 &&
        clients[1].sock > 0 &&
        clients[0].dh_pubkey &&
        clients[1].dh_pubkey &&
        !g_keys_exchanged)
    {
        exchange_keys();
        g_keys_exchanged = 1;
    }

    pthread_mutex_unlock(&g_mutex);

    while (1) {
        int len = read(sock, buf, sizeof(buf));
        if (len <= 0) {
            pthread_mutex_lock(&g_mutex);
            clients[idx].sock = -1;
            g_keys_exchanged = 0;
        pthread_mutex_unlock(&g_mutex);
        close(sock);
        break;
    }

        // 3) 받은 암호문을 상대 소켓에 그대로 포워딩
        int other = other_index(idx);
        pthread_mutex_lock(&g_mutex);
        int other_sock = clients[other].sock;
        pthread_mutex_unlock(&g_mutex);

        if (other_sock > 0) write(other_sock, buf, len);
    }

    return NULL;
}

int main() {
    int serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(5555);
    serv.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(serv_sock, (struct sockaddr *)&serv, sizeof(serv)) < 0) return 1;
    if (listen(serv_sock, 2) < 0) return 1;

    printf("SafeTalk 서버 실행 중\n");

    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].sock = -1;
        clients[i].dh_pubkey = NULL;
    }

    while (1) {
        struct sockaddr_in clnt;
        socklen_t sz = sizeof(clnt);

        int clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt, &sz);
        if (clnt_sock < 0) continue;

        int idx = (clients[0].sock <= 0) ? 0 : 1;
        clients[idx].sock = clnt_sock;

        int *arg = malloc(sizeof(int));
        *arg = idx;

        pthread_t tid;
        pthread_create(&tid, NULL, client_thread, arg);
        pthread_detach(tid);
    }

    close(serv_sock);
    return 0;
}
