// SafeTalk - 암호화 1:1 메신저 클라이언트
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include "crypto.h"

#define BUF_SIZE 4096

int g_sock = -1;
volatile int g_running = 1;
unsigned char g_aes_key[32];
char g_my_nick[32];

void trim_newline(char *s) {
    s[strcspn(s, "\n")] = 0;
}

// 키 교환
int do_key_exchange(int sock) {
    // 1) 각자 X25519 키 쌍 생성 후 공개키 교환
    EVP_PKEY *my_key = generate_dh_keypair();
    if (!my_key) return -1;

    unsigned char my_pub[200];
    size_t my_pub_len = sizeof(my_pub);

    if (EVP_PKEY_get_raw_public_key(my_key, my_pub, &my_pub_len) <= 0) return -1;

    if (write(sock, &my_pub_len, sizeof(my_pub_len)) != sizeof(my_pub_len)) return -1;
    if (write(sock, my_pub, my_pub_len) != (ssize_t)my_pub_len) return -1;

    size_t peer_len;
    if (read(sock, &peer_len, sizeof(peer_len)) != sizeof(peer_len)) return -1;

    unsigned char peer_buf[200];
    if (read(sock, peer_buf, peer_len) != (ssize_t)peer_len) return -1;

    EVP_PKEY *peer_key =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_buf, peer_len);
    if (!peer_key) return -1;

    // 2) 공유 비밀키 → AES 세션키 파생
    size_t secret_len = 0;
    unsigned char *secret = derive_shared_secret(my_key, peer_key, &secret_len);
    if (!secret) return -1;

    derive_aes_key_from_secret(secret, secret_len, g_aes_key);

    free(secret);
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer_key);
    return 0;
}

// 메시지 송신
void *send_thread(void *arg) {
    char input[BUF_SIZE];
    char msg[BUF_SIZE];

    while (g_running) {
        printf("> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) break;
        trim_newline(input);

        if (!strcmp(input, "/exit")) {
            // __LEFT__ 신호로 상대에게 종료 알림
            send_secure_message(g_sock, g_aes_key, "__LEFT__");
            g_running = 0;
            break;
        }

        snprintf(msg, sizeof(msg), "%s: %s", g_my_nick, input);

        if (send_secure_message(g_sock, g_aes_key, msg) < 0) break;

        printf("[나] %s\n", msg);
    }
    return NULL;
}

// 메시지 수신
void *recv_thread(void *arg) {
    char plain[BUF_SIZE];

    while (g_running) {
        int len = recv_secure_message(g_sock, g_aes_key, plain);

        if (!g_running) break;
        if (len == 0) {
            printf("\n[client] 상대가 연결을 종료했습니다.\n");
            g_running = 0;
            break;
        }
        if (len < 0) {
            printf("\n[client] 수신 오류\n");
            g_running = 0;
            break;
        }

        if (!strcmp(plain, "__LEFT__")) {
            // 상대가 /exit 입력한 경우
            printf("\n[client] 상대가 방에서 나갔습니다.\n> ");
            g_running = 0;
            break;
        }

        printf("\n[상대] %s\n> ", plain);
        fflush(stdout);
    }
    return NULL;
}

// 서버 연결 및 초기 설정 
int connect_and_handshake() {
    g_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_sock < 0) return -1;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(5555);
    struct hostent *host = gethostbyname("server");
    if (!host) {
        printf("Docker DNS 사용 불가 → 로컬 모드로 전환\n");
        host = gethostbyname("127.0.0.1");
    }

    if (!host) {
        printf("서버 주소를 찾을 수 없습니다.\n");
        close(g_sock);
        return -1;
    }
    memcpy(&serv.sin_addr, host->h_addr_list[0], host->h_length);


    if (connect(g_sock, (struct sockaddr *)&serv, sizeof(serv)) < 0) {
        close(g_sock);
        return -1;
    }

    char nickbuf[32] = {0};
    strncpy(nickbuf, g_my_nick, sizeof(nickbuf) - 1);
    if (write(g_sock, nickbuf, sizeof(nickbuf)) != sizeof(nickbuf)) return -1;

    if (do_key_exchange(g_sock) < 0) return -1;

    return 0;
}

int main(int argc, char *argv[]) {
    int auto_mode = 0;

    // 1) argv로 닉네임/모드 설정
    memset(g_my_nick, 0, sizeof(g_my_nick));
    if (argc >= 2) {
        strncpy(g_my_nick, argv[1], sizeof(g_my_nick) - 1);
    }
    if (argc >= 3 && strcmp(argv[2], "--auto") == 0) {
        auto_mode = 1;
    }

    // 2) 닉네임이 아직 비었으면 직접 입력
    if (strlen(g_my_nick) == 0) {
        printf("닉네임 입력: ");
        if (!fgets(g_my_nick, sizeof(g_my_nick), stdin)) return 0;
        trim_newline(g_my_nick);
        if (strlen(g_my_nick) == 0) strcpy(g_my_nick, "User");
    }

    // 3) 자동 모드: 로비 없이 바로 Room 1 접속
    if (auto_mode) {
        printf("\n[자동 모드] 닉네임: %s, Room 1 자동 입장\n", g_my_nick);

        if (connect_and_handshake() < 0) {
            printf("[client] 서버 연결 실패\n");
            return 1;
        }

        printf("[Room 1] 입장 완료. /exit 입력 시 퇴장합니다.\n\n");

        g_running = 1;

        pthread_t ts, tr;
        pthread_create(&ts, NULL, send_thread, NULL);
        pthread_create(&tr, NULL, recv_thread, NULL);

        pthread_join(ts, NULL);
        g_running = 0;
        shutdown(g_sock, SHUT_RDWR);
        pthread_join(tr, NULL);

        close(g_sock);
        g_sock = -1;

        printf("\n[Room 1] 방에서 나갔습니다.\n");
        return 0;
    }

    // 4) 일반 모드: 기존 로비 메뉴 유지
    while (1) {
        printf("\n===== SafeTalk 로비 =====\n");
        printf("1. 들어가기 (Room 1)\n");
        printf("2. 종료\n");
        printf("선택: ");

        char menu[8];
        if (!fgets(menu, sizeof(menu), stdin)) break;
        trim_newline(menu);

        if (!strcmp(menu, "2")) {
            printf("프로그램을 종료합니다.\n");
            break;
        }
        if (strcmp(menu, "1")) {
            printf("잘못된 선택입니다.\n");
            continue;
        }

        printf("\n[로비] Room 1 입장 중...\n");

        if (connect_and_handshake() < 0) {
            printf("[client] 서버 연결 실패\n");
            continue;
        }

        printf("[Room 1] 입장 완료. /exit 입력 시 퇴장합니다.\n\n");

        g_running = 1;

        pthread_t ts, tr;
        pthread_create(&ts, NULL, send_thread, NULL);
        pthread_create(&tr, NULL, recv_thread, NULL);

        pthread_join(ts, NULL);
        g_running = 0;
        shutdown(g_sock, SHUT_RDWR);
        pthread_join(tr, NULL);

        close(g_sock);
        g_sock = -1;

        printf("\n[Room 1] 방에서 나갔습니다.\n");
        // while 루프 때문에 자동으로 다시 로비로 돌아감
    }

    return 0;
}
