/* http1.c - HTTP/1.0 · 1.1 파서
 *  메시지 = 시작줄\r\n + 헤더\r\n... + \r\n + [본문]
 *  - 헤더가 세그먼트 여러 개에 걸치면 hbuf에 모았다가 빈 줄이 오면 한 번에 출력
 *  - 본문 길이: Content-Length / chunked / 연결 종료까지(HTTP/1.0 응답 등)
 *  - 본문이 다음 세그먼트로 이어져도 끝까지 따라가며 출력
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include "http1.h"

#define PREVIEW 200

static const char *starts[] = {
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ",
    "CONNECT ", "TRACE ", "HTTP/1."
};

int looks_like_http1(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < sizeof(starts) / sizeof(starts[0]); i++) {
        size_t k = strlen(starts[i]);
        if (n >= k && memcmp(p, starts[i], k) == 0) return 1;
    }
    return 0;
}

void h1_reset(h1_dir_t *d)
{
    d->state = H1_IDLE;
    d->hlen = 0;
    d->body_mode = BODY_NONE;
    d->body_left = d->body_seen = 0;
    d->body_total = -1;
    memset(d->tail, 0, sizeof(d->tail));
}

static void print_safe(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        putchar(isprint((unsigned char)s[i]) ? s[i] : '.');
}

/* "\r\n\r\n" 위치 찾기 (빈 줄 끝 다음 인덱스 반환, 없으면 0) */
static size_t find_hdr_end(const char *b, size_t n)
{
    for (size_t i = 0; i + 3 < n; i++)
        if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n')
            return i + 4;
    return 0;
}

/* 헤더 블록(시작줄~빈 줄)을 출력하고 본문 방식을 정한다 */
static void parse_message(h1_dir_t *d, int dirn, const char *b, size_t n, int *req_head)
{
    char line[2048];
    size_t off = 0;
    int status = 0, is_head = 0, is_http10 = 0;
    long clen = -1;
    int chunked = 0, conn_close = 0;

    /* ── 시작줄 ── */
    const char *eol = memchr(b, '\n', n);
    size_t ln = eol ? (size_t)(eol - b) : n;
    size_t cp = ln < sizeof(line) - 1 ? ln : sizeof(line) - 1;
    memcpy(line, b, cp); line[cp] = '\0';
    if (cp && line[cp - 1] == '\r') line[cp - 1] = '\0';
    off = ln + 1;

    if (strncmp(line, "HTTP/", 5) == 0) {
        char ver[16] = "", reason[256] = "";
        sscanf(line, "%15s %d %255[^\r\n]", ver, &status, reason);
        is_http10 = strcmp(ver, "HTTP/1.0") == 0;
        printf("  [HTTP/1.x 응답 Response]\n");
        printf("    Version     : %s\n", ver);
        printf("    Status Code : %d\n", status);
        printf("    Reason      : %s\n", reason);
    } else {
        char method[16] = "", uri[768] = "", ver[16] = "";
        sscanf(line, "%15s %767s %15s", method, uri, ver);
        is_head = strcmp(method, "HEAD") == 0;
        is_http10 = strcmp(ver, "HTTP/1.0") == 0;
        printf("  [HTTP/1.x 요청 Request]\n");
        printf("    Method      : %s\n", method);
        printf("    URI         : %s\n", uri);
        printf("    Version     : %s\n", ver[0] ? ver : "(none -> HTTP/0.9)");
    }

    /* ── 헤더 ── */
    printf("    Headers     :\n");
    while (off < n) {
        const char *s = b + off;
        const char *e = memchr(s, '\n', n - off);
        size_t len = e ? (size_t)(e - s) : n - off;
        off += len + 1;
        if (len && s[len - 1] == '\r') len--;
        if (len == 0) break;                         /* 빈 줄 = 헤더 끝 */
        printf("      ");
        print_safe(s, len);
        putchar('\n');

        cp = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
        memcpy(line, s, cp); line[cp] = '\0';
        if (strncasecmp(line, "Content-Length:", 15) == 0) clen = atol(line + 15);
        else if (strncasecmp(line, "Transfer-Encoding:", 18) == 0 && strcasestr(line, "chunked")) chunked = 1;
        else if (strncasecmp(line, "Connection:", 11) == 0 && strcasestr(line, "close")) conn_close = 1;
    }

    /* ── 본문 방식 결정 (RFC 9112 6.3) ── */
    d->body_seen = 0;
    d->body_total = -1;
    memset(d->tail, 0, sizeof(d->tail));
    if (dirn == 0) {                                  /* 요청 */
        *req_head = is_head;
        if (chunked)        d->body_mode = BODY_CHUNKED;
        else if (clen > 0)  { d->body_mode = BODY_LENGTH; d->body_left = d->body_total = clen; }
        else                d->body_mode = BODY_NONE;
    } else {                                          /* 응답 */
        if (*req_head || status / 100 == 1 || status == 204 || status == 304)
                            d->body_mode = BODY_NONE;
        else if (chunked)   d->body_mode = BODY_CHUNKED;
        else if (clen >= 0) { d->body_mode = clen ? BODY_LENGTH : BODY_NONE; d->body_left = d->body_total = clen; }
        else                d->body_mode = BODY_UNTIL_CLOSE;   /* 길이 정보 없음 -> FIN까지 */
        *req_head = 0;
    }
    (void)is_http10; (void)conn_close;

    if (d->body_mode == BODY_NONE) printf("    Body        : (없음)\n");
}

/* 본문 조각 출력 */
static void body_piece(h1_dir_t *d, const uint8_t *p, size_t k)
{
    int first = d->body_seen == 0;
    d->body_seen += (long)k;
    if (first) {
        printf("    Body        : %zu bytes", k);
        if (d->body_mode == BODY_LENGTH)       printf(" (Content-Length %ld 중)", d->body_total);
        else if (d->body_mode == BODY_CHUNKED) printf(" (chunked)");
        else                                    printf(" (연결 종료까지)");
        printf("\n      preview   : ");
        print_safe((const char *)p, k < PREVIEW ? k : PREVIEW);
        if (k > PREVIEW) printf(" ...");
        putchar('\n');
    } else {
        printf("  [HTTP/1.x 본문 이어짐] +%zu bytes (누적 %ld", k, d->body_seen);
        if (d->body_mode == BODY_LENGTH) printf(" / %ld", d->body_total);
        printf(")\n");
    }
}

static void body_done(h1_dir_t *d, const char *why)
{
    printf("  [HTTP/1.x 본문 완료] 총 %ld bytes (%s)\n", d->body_seen, why);
    d->state = H1_IDLE;
    d->body_mode = BODY_NONE;
}

void h1_feed(h1_dir_t *d, int dirn, const uint8_t *p, size_t n, int *req_head)
{
    while (n > 0) {
        if (d->state == H1_IDLE) {
            if (!looks_like_http1(p, n)) {
                printf("  [HTTP/1.x] 메시지 시작이 아닌 데이터 %zu bytes (건너뜀)\n", n);
                return;
            }
            d->state = H1_HEADERS;
            d->hlen = 0;
        }

        if (d->state == H1_HEADERS) {
            size_t room = H1_HDR_MAX - d->hlen;
            size_t k = n < room ? n : room;
            size_t old = d->hlen;
            memcpy(d->hbuf + d->hlen, p, k);
            d->hlen += k;
            size_t end = find_hdr_end(d->hbuf, d->hlen);
            if (!end) {
                if (d->hlen == H1_HDR_MAX) {
                    printf("  [HTTP/1.x] 헤더가 %d bytes를 넘어서 잘림\n", H1_HDR_MAX);
                    parse_message(d, dirn, d->hbuf, d->hlen, req_head);
                    h1_reset(d);
                } else {
                    printf("  [HTTP/1.x] 헤더 조각 %zu bytes 수집 중 (다음 세그먼트 대기)\n", k);
                }
                return;
            }
            parse_message(d, dirn, d->hbuf, end, req_head);
            size_t used = end - old;                    /* 이번 세그먼트에서 헤더로 쓴 바이트 */
            p += used; n -= used;
            d->hlen = 0;
            d->state = d->body_mode == BODY_NONE ? H1_IDLE : H1_BODY;
            continue;
        }

        /* H1_BODY */
        if (d->body_mode == BODY_LENGTH) {
            size_t k = (long)n < d->body_left ? n : (size_t)d->body_left;
            body_piece(d, p, k);
            d->body_left -= (long)k;
            p += k; n -= k;
            if (d->body_left == 0) body_done(d, "Content-Length 만큼 받음");
        } else if (d->body_mode == BODY_CHUNKED) {
            body_piece(d, p, n);
            /* 직전 4바이트 + 이번 데이터에서 마지막 청크 표시 "0\r\n\r\n" 찾기 */
            char win[4 + 64];
            size_t t = n < 64 ? n : 64;
            memcpy(win, d->tail, 4);
            memcpy(win + 4, p + n - t, t);
            int end = 0;
            for (size_t i = 0; i + 5 <= 4 + t; i++)
                if (memcmp(win + i, "0\r\n\r\n", 5) == 0) end = 1;
            memcpy(d->tail, win + t, 4);
            if (end) body_done(d, "마지막 청크(0) 받음");
            return;
        } else {                                        /* BODY_UNTIL_CLOSE */
            body_piece(d, p, n);
            return;
        }
    }
}

void h1_close(h1_dir_t *d, int dirn)
{
    (void)dirn;
    if (d->state == H1_BODY) {
        if (d->body_mode == BODY_UNTIL_CLOSE) body_done(d, "연결 종료(FIN)로 본문 끝");
        else printf("  [HTTP/1.x] 본문을 다 받기 전에 연결 종료 (%ld bytes)\n", d->body_seen);
    }
    h1_reset(d);
}
