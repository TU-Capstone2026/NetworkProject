#include "mail_demo.h"

#include <string.h>
#include <strings.h>

static bool send_pop_message(struct connection *conn, const struct mailbox *mailbox)
{
    if (fprintf(conn->output, "+OK %zu octets\r\n", mailbox->size) < 0)
        return false;
    const char *line = mailbox->data;
    const char *end = line + mailbox->size;
    while (line < end) {
        const char *next = strchr(line, '\n') + 1;
        if (*line == '.' && fputc('.', conn->output) == EOF)
            return false;
        size_t length = (size_t)(next - line);
        if (fwrite(line, 1, length, conn->output) != length)
            return false;
        line = next;
    }
    return send_text(conn, ".\r\n");
}

void serve_pop3(struct connection *conn, const struct mailbox *mailbox)
{
    enum { USER, PASS, TRANSACTION } state = USER;
    char line[LINE_SIZE];
    if (!send_text(conn, "+OK localhost POP3 demo\r\n"))
        return;
    while (read_line(conn, line)) {
        if (strcasecmp(line, "QUIT\r\n") == 0) {
            send_text(conn, "+OK Bye\r\n");
            return;
        }
        const char *response = "-ERR Unexpected command for this demo session\r\n";
        if (state != TRANSACTION && strcasecmp(line, "USER demo\r\n") == 0) {
            state = PASS;
            response = "+OK User accepted\r\n";
        } else if (state == PASS && strcasecmp(line, "PASS demo\r\n") == 0) {
            state = TRANSACTION;
            response = "+OK Mailbox ready\r\n";
        } else if (state == TRANSACTION && strcasecmp(line, "RETR 1\r\n") == 0) {
            if (mailbox->size > 0) {
                if (!send_pop_message(conn, mailbox))
                    return;
                continue;
            }
            response = "-ERR No such message\r\n";
        }
        if (!send_text(conn, response))
            return;
    }
}
