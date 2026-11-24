#include "mail_demo.h"

#include <string.h>
#include <strings.h>

/* Drain DATA through its terminator even when the message is too large. */
static bool receive_mail(struct connection *conn, struct mailbox *mailbox)
{
    struct mailbox pending = {0};
    bool too_large = false;
    char line[LINE_SIZE];
    if (!send_text(conn, "354 End data with <CRLF>.<CRLF>\r\n"))
        return false;
    while (read_line(conn, line)) {
        if (strcmp(line, ".\r\n") == 0) {
            if (too_large)
                return send_text(conn, "552 Message too large\r\n");
            *mailbox = pending;
            return send_text(conn, "250 Message stored\r\n");
        }
        const char *data = line[0] == '.' ? line + 1 : line;
        size_t bytes = strlen(data);
        if (bytes > sizeof pending.data - 1 - pending.size) {
            too_large = true;
            continue;
        }
        memcpy(pending.data + pending.size, data, bytes);
        pending.size += bytes;
    }
    return false;
}

void serve_smtp(struct connection *conn, struct mailbox *mailbox)
{
    enum { GREETING, SENDER, RECIPIENT, DATA } state = GREETING;
    char line[LINE_SIZE];
    if (!send_text(conn, "220 localhost SMTP demo\r\n"))
        return;
    while (read_line(conn, line)) {
        if (strcasecmp(line, "QUIT\r\n") == 0) {
            send_text(conn, "221 Bye\r\n");
            return;
        }
        const char *response = "503 Unexpected command for this demo session\r\n";
        if (strncasecmp(line, "EHLO ", 5) == 0) {
            state = SENDER;
            response = "250 localhost\r\n";
        } else if (state == SENDER && strncasecmp(line, "MAIL FROM:", 10) == 0) {
            state = RECIPIENT;
            response = "250 Sender OK\r\n";
        } else if (state == RECIPIENT && strncasecmp(line, "RCPT TO:", 8) == 0) {
            state = DATA;
            response = "250 Recipient OK\r\n";
        } else if (state == DATA && strcasecmp(line, "DATA\r\n") == 0) {
            if (!receive_mail(conn, mailbox))
                return;
            state = SENDER;
            continue;
        }
        if (!send_text(conn, response))
            return;
    }
}
