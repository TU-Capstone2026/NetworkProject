# 미니 Wireshark - HTTP/1.0 · 1.1 · 2 통합 스니퍼
CC      = gcc
CFLAGS  = -Wall -Wextra -O2
TARGET  = http_sniffer
SRCS    = main.c http1.c http2.c hpack.c

$(TARGET): $(SRCS) http1.h http2.h hpack.h hpack_tables.h
	$(CC) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -f $(TARGET)
