CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
ifeq ($(shell uname -s),Darwin)
CAPTURE_LIBS = -lpcap
endif

all: mail_server mail_capture

mail_server: main.c smtp.c pop3.c imap.c mail_demo.h
	$(CC) $(CFLAGS) main.c smtp.c pop3.c imap.c -o $@

mail_capture: mail_capture.c
	$(CC) $(CFLAGS) mail_capture.c $(CAPTURE_LIBS) -o $@
