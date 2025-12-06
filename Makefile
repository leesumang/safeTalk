CC = gcc
CFLAGS = -Wall -O2 \
	-I/opt/homebrew/opt/openssl@3/include \
	-Iinclude
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
TARGETS = server client

all: $(TARGETS)

server: src/server.c src/crypto.c include/crypto.h
	$(CC) $(CFLAGS) -o server src/server.c src/crypto.c $(LDFLAGS)

client: src/client.c src/crypto.c include/crypto.h
	$(CC) $(CFLAGS) -o client src/client.c src/crypto.c $(LDFLAGS)

clean:
	rm -f $(TARGETS)
