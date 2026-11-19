/* http2.h - HTTP/2 프레임 파서 (방향별 재조립 + HPACK) */
#ifndef HTTP2_H
#define HTTP2_H

#include <stddef.h>
#include <stdint.h>
#include "hpack.h"

#define H2_BUF   65536   /* 프레임 재조립 버퍼 (기본 최대 프레임 16KB) */
#define H2_HBLK  65536   /* HEADERS + CONTINUATION 헤더 블록 모으는 버퍼 */

typedef struct {
    uint8_t     buf[H2_BUF];
    size_t      len;
    int         preface_done;
    uint8_t     hblk[H2_HBLK];
    size_t      hblen;
    uint32_t    hstream;      /* 모으는 중인 헤더 블록의 스트림 */
    int         hcollect;     /* END_HEADERS 기다리는 중 */
    int         hend_stream;
    hpack_ctx_t hp;           /* 이 방향으로 오는 헤더를 푸는 HPACK 상태 */
} h2_dir_t;

extern const char H2_PREFACE[24];

int  h2_is_preface(const uint8_t *p, size_t n);     /* 앞부분이 프리페이스와 일치? */
void h2_init(h2_dir_t *d);
void h2_feed(h2_dir_t *d, int dirn, const uint8_t *p, size_t n);
void h2_reset(h2_dir_t *d);                         /* TCP gap: 프레임 경계 잃음 */
void h2_free(h2_dir_t *d);

#endif
