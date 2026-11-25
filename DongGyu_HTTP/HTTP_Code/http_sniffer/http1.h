/* http1.h - HTTP/1.0 · 1.1 텍스트 파서 (방향별 상태 유지) */
#ifndef HTTP1_H
#define HTTP1_H

#include <stddef.h>
#include <stdint.h>

#define H1_HDR_MAX 16384

enum { H1_IDLE, H1_HEADERS, H1_BODY };
enum { BODY_NONE, BODY_LENGTH, BODY_CHUNKED, BODY_UNTIL_CLOSE };

typedef struct {
    int    state;
    char   hbuf[H1_HDR_MAX];   /* 헤더가 세그먼트 여러 개에 걸칠 때 모아두는 곳 */
    size_t hlen;
    int    body_mode;
    long   body_left;          /* BODY_LENGTH: 남은 바이트 */
    long   body_seen;          /* 지금까지 받은 본문 바이트 */
    long   body_total;         /* Content-Length (모르면 -1) */
    char   tail[5];            /* chunked 끝("0\r\n\r\n") 찾기용 직전 바이트 */
} h1_dir_t;

int  looks_like_http1(const uint8_t *p, size_t n);
/* dirn: 0 = 클라->서버(요청), 1 = 서버->클라(응답)
   req_head: 이 응답에 대응하는 요청이 HEAD였는지 (본문 없음) */
void h1_feed(h1_dir_t *d, int dirn, const uint8_t *p, size_t n, int *req_head);
void h1_close(h1_dir_t *d, int dirn);   /* FIN/RST: 연결 종료로 끝나는 본문 마무리 */
void h1_reset(h1_dir_t *d);

#endif
