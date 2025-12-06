# SafeTalk – 실시간 1:1 암호화 메신저 (with Docker Auto Run)

SafeTalk은 네트워크 상에서 메시지 평문 노출을 방지하기 위해  
OpenSSL 기반 **X25519(ECDH)** 키 교환과 **AES-256-CBC** 암호화를 적용한  
1:1 보안 메신저입니다.

또한 Docker Compose를 이용해 **서버 + 클라이언트 자동 실행**,  
클라이언트 자동 입장 기능을 지원합니다.

---

## ✨ 주요 기능

- 1:1 실시간 채팅(TCP)
- X25519 키 교환 → 공유 비밀키 생성
- SHA-256 기반 AES-256 세션키 도출
- AES-256-CBC 암호화/복호화
- SHA-256 무결성 검증
- `/exit` 기반 퇴장 처리
- Docker 자동 접속(Alice/Bob)

---

## 📁 디렉토리 구조

```safeTalk/
├── src/
│   ├── server.c
│   ├── client.c
│   └── crypto.c
├── include/
│   └── crypto.h
├── Makefile
├── Dockerfile.server
├── Dockerfile.client
├── docker-compose.yml
├── .dockerignore
└── README.md
```

---

## 🔧 3. 로컬 빌드 및 실행

### 3.1 빌드

OpenSSL 개발 헤더가 설치되어 있어야 합니다.

```bash
make
```

생성되는 실행 파일:

- server
- client

### 3.2 서버 실행

```bash
./server
```

### 3.3 클라이언트 실행

```bash
./client
```

실행 순서:

1. 닉네임 입력
2. 로비에서 1 입력 → Room 1 입장
3. 메시지 입력
4. `/exit` 입력 시 종료

---

## 🔐 4. 암호화 프로토콜 개요

### 4.1 키 교환 (X25519)

1. 클라이언트 A/B X25519 키쌍 생성
2. 서버가 공개키 전달
3. 클라이언트는 ECDH로 공유 비밀키 계산
4. 공유 비밀키 → SHA-256 → AES-256 세션키

### 4.2 메시지 포맷

```
[4 bytes]   total_length
[16 bytes]  IV
[n bytes]   ciphertext
[32 bytes]  SHA-256(ciphertext)
```

---

## 🐳 5. Docker 실행 방법

### 5.1 빌드 + 실행

```bash
docker compose up --build
```

자동 실행되는 컨테이너:

- safetalk-server
- safetalk-client1 (Alice)
- safetalk-client2 (Bob)

자동 입장 로그:

```
[자동 모드] 닉네임: Alice, Room 1 자동 입장
[자동 모드] 닉네임: Bob, Room 1 자동 입장
```

### 5.2 실제 채팅 입력은 attach에서

```bash
docker attach safetalk-client1
docker attach safetalk-client2
```

채팅 예:

```
> 안녕 Bob!
[상대] Alice: 안녕 Bob!
```

### detach (컨테이너 종료 안 함)

```
Ctrl + P, Ctrl + Q
```

---

## ⚙ 6. Docker 구성 요소 요약

### Dockerfile.server

- 소스 복사 후 컨테이너 내에서 `make server` 수행
- 로컬 실행 파일 반입 방지 `.dockerignore` 적용

### Dockerfile.client

- `make client` 수행
- compose가 실행 명령(`./client Alice --auto`)을 override

### docker-compose.yml

- server + client1 + client2 정의
- depends_on으로 순서 보장
- 클라이언트 자동 입장

---

## 🛡 7. 서버 안정성 패치

빠른 접속 환경(Docker)에서 `dh_pubkey == NULL` 문제 방지:

```c
if (clients[0].sock > 0 &&
    clients[1].sock > 0 &&
    clients[0].dh_pubkey &&
    clients[1].dh_pubkey &&
    !g_keys_exchanged)
{
    exchange_keys();
    g_keys_exchanged = 1;
}
```

---

## 🚀 8. 향후 개선 방향

- AES-GCM 인증된 암호 적용
- 그룹 채팅
- 사용자 인증
- 메시지 저장 로그 서버
- WebSocket 기반 확장
- GUI / 모바일 버전

---

SafeTalk은 실습용 보안 메신저 프로젝트이며,  
암호화 통신 구현 + Docker 배포 자동화를 목표로 합니다.
