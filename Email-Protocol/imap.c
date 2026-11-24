#include "mail_demo.h"

#include <string.h>
#include <strings.h>

void serve_imap(struct connection *conn, const struct mailbox *mailbox)
{
    enum { LOGIN, SELECT, FETCH } state = LOGIN;
    char line[LINE_SIZE];
    if (!send_text(conn, "* OK localhost IMAP demo\r\n"))
        return;
    while (read_line(conn, line)) {
        char *command = strchr(line, ' ');
        if (!command) {
            if (!send_text(conn, "* BAD Expected a tag and command\r\n"))
                return;
            continue;
        }
        *command++ = '\0';
        const char *response = "BAD Unexpected command for this demo session";
        bool logout = strcasecmp(command, "LOGOUT\r\n") == 0;
        if (strcasecmp(command, "CAPABILITY\r\n") == 0) {
            if (!send_text(conn, "* CAPABILITY IMAP4rev1\r\n")) return;
            response = "OK CAPABILITY completed";
        } else if (logout) {
            if (!send_text(conn, "* BYE Logging out\r\n"))
                return;
            response = "OK LOGOUT completed";
        } else if (state == LOGIN && (strcasecmp(command, "LOGIN demo demo\r\n") == 0 ||
                   strcasecmp(command, "LOGIN demo \"demo\"\r\n") == 0)) {
            state = SELECT;
            response = "OK LOGIN completed";
        } else if (state != LOGIN && (strcasecmp(command, "SELECT INBOX\r\n") == 0 || strcasecmp(command, "EXAMINE INBOX\r\n") == 0)) {
            if (fprintf(conn->output, "* FLAGS (\\Seen)\r\n* %d EXISTS\r\n"
                        "* OK [UIDVALIDITY 1] UIDs valid\r\n"
                        "* OK [UIDNEXT %d] Next UID\r\n",
                        mailbox->size > 0 ? 1 : 0, mailbox->size > 0 ? 2 : 1) < 0)
                return;
            state = FETCH;
            response = "OK [READ-ONLY] SELECT completed";
        } else if (state == FETCH && (strcasecmp(command, "FETCH 1 BODY.PEEK[]\r\n") == 0 || strcasecmp(command, "FETCH 1 (BODY.PEEK[])\r\n") == 0)) {
            if (mailbox->size > 0) {
                if (fprintf(conn->output, "* 1 FETCH (BODY[] {%zu}\r\n", mailbox->size) < 0 ||
                    fwrite(mailbox->data, 1, mailbox->size, conn->output) != mailbox->size ||
                    fputs(")\r\n", conn->output) == EOF)
                    return;
                response = "OK FETCH completed";
            } else {
                response = "NO No such message";
            }
        }
        if (fprintf(conn->output, "%s %s\r\n", line, response) < 0 ||
            fflush(conn->output) != 0 || logout)
            return;
    }
}
