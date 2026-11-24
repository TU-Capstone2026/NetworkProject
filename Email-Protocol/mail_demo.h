#ifndef MAIL_DEMO_H
#define MAIL_DEMO_H

#include <stdbool.h>
#include <stdio.h>

#define LINE_SIZE 1024
#define MAILBOX_CAPACITY 8192

struct mailbox {
    char data[MAILBOX_CAPACITY];
    size_t size;
};

struct connection {
    FILE *input;
    FILE *output;
};

bool send_text(struct connection *conn, const char *text);
bool read_line(struct connection *conn, char line[LINE_SIZE]);

void serve_smtp(struct connection *conn, struct mailbox *mailbox);
void serve_pop3(struct connection *conn, const struct mailbox *mailbox);
void serve_imap(struct connection *conn, const struct mailbox *mailbox);

#endif
