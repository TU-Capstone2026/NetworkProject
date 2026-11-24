#define _POSIX_C_SOURCE 200809L
#include "mail_demo.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

enum protocol { SMTP, POP3, IMAP, PROTOCOL_COUNT };
static const int ports[] = {2525, 11110, 11430};
static const char *const names[] = {"smtp", "pop3", "imap"};

static bool open_streams(int fd, struct connection *conn)
{
    const struct timeval timeout = {.tv_sec = 10};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    int output_fd = dup(fd);
    conn->input = fdopen(fd, "r");
    conn->output = output_fd < 0 ? NULL : fdopen(output_fd, "w");
    if (conn->input && conn->output)
        return true;
    if (conn->input)
        fclose(conn->input);
    else
        close(fd);
    if (conn->output)
        fclose(conn->output);
    else if (output_fd >= 0)
        close(output_fd);
    return false;
}

bool send_text(struct connection *conn, const char *text)
{
    return fputs(text, conn->output) != EOF && fflush(conn->output) == 0;
}

bool read_line(struct connection *conn, char line[LINE_SIZE])
{
    if (!fgets(line, LINE_SIZE, conn->input))
        return false;
    size_t length = strlen(line);
    return length >= 2 && strcmp(line + length - 2, "\r\n") == 0;
}

static int listen_local(int port)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((unsigned short)port),
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
    };
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    const struct sockaddr *endpoint = (const struct sockaddr *)&address;
    int reuse = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse) == 0 &&
            bind(fd, endpoint, sizeof address) == 0 && listen(fd, 4) == 0)
            return fd;

    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    struct pollfd listeners[PROTOCOL_COUNT+1];
    struct mailbox mailbox = {0};
    for (int i = 0; i < PROTOCOL_COUNT; ++i) {
        listeners[i] = (struct pollfd){.fd = listen_local(ports[i]), .events = POLLIN};
        if (listeners[i].fd < 0) {
            fprintf(stderr, "%s port %d: %s\n", names[i], ports[i], strerror(errno));
            return EXIT_FAILURE;
        }
    }
    listeners[PROTOCOL_COUNT] = (struct pollfd){.fd = STDIN_FILENO, .events = POLLIN};
    puts("READY");
    fflush(stdout);
    while (poll(listeners, PROTOCOL_COUNT+1, -1) >= 0) {
        if (listeners[PROTOCOL_COUNT].revents) {
            char ack;
            if (read(STDIN_FILENO, &ack, 1) != 1) return 0;
            listeners[SMTP].events = POLLIN;
        }
        for (int i = 0; i < PROTOCOL_COUNT; ++i) {
            if (!(listeners[i].revents & POLLIN))
                continue;
            struct connection conn;
            int fd = accept(listeners[i].fd, NULL, NULL);
            if (fd < 0 || !open_streams(fd, &conn)) {
                perror("open client connection");
                continue;
            }
            if (i == SMTP) {
                mailbox.size = 0;
                serve_smtp(&conn, &mailbox);
                if (mailbox.size) {
                    /* Keep this message until both readers finish. */
                    listeners[SMTP].events = 0;
                    puts("STORED");
                    fflush(stdout);
                }
            }
            else if (i == POP3)
                serve_pop3(&conn, &mailbox);
            else
                serve_imap(&conn, &mailbox);
            fclose(conn.output);
            fclose(conn.input);
        }
    }
    perror("poll");
    return EXIT_FAILURE;
}

