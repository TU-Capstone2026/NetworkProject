CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g
TARGET  = bt_sniffer
TESTGEN = test/bt_testgen
OBJS    = main.o bittorrent.o bencode.o

all: $(TARGET) $(TESTGEN)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

# 루프백 테스트 트래픽 생성기
$(TESTGEN): test/bt_testgen.c
	$(CC) $(CFLAGS) -o $@ $<

main.o: main.c common.h bittorrent.h
bittorrent.o: bittorrent.c bittorrent.h bencode.h common.h
bencode.o: bencode.c bencode.h

clean:
	rm -f $(TARGET) $(OBJS) $(TESTGEN)

.PHONY: all clean
