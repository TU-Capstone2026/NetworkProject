/* hpack.h - HPACK(RFC 7541) 디코더: HTTP/2 HEADERS 블록 -> 헤더 목록 */
#ifndef HPACK_H
#define HPACK_H

#include <stddef.h>
#include <stdint.h>

#define HPACK_MAX_DYN   128      /* 동적 테이블 최대 항목 수 */
#define HPACK_MAX_FIELD 64       /* 블록 하나에서 꺼낼 최대 헤더 수 */
#define HPACK_STR_MAX   1024     /* 이름/값 최대 길이 (넘으면 잘라서 보관) */

typedef struct {
    char *name;
    char *value;
} hpack_field_t;

/* 방향(클라->서버, 서버->클라)마다 하나씩 쓰는 디코딩 상태 */
typedef struct {
    hpack_field_t dyn[HPACK_MAX_DYN];   /* dyn[0] = 가장 최근 항목 (인덱스 62) */
    int    count;
    size_t size;                        /* 항목 크기 합 (이름+값+32) */
    size_t max_size;                    /* 기본 4096 */
} hpack_ctx_t;

void hpack_init(hpack_ctx_t *c);
void hpack_free(hpack_ctx_t *c);

/* 헤더 블록 하나를 디코딩해서 out[]에 채운다. 반환: 헤더 개수, 오류면 -1
   out[i].name / value 는 호출한 쪽이 hpack_fields_free()로 해제 */
int  hpack_decode(hpack_ctx_t *c, const uint8_t *blk, size_t len,
                  hpack_field_t *out, int max_out);
void hpack_fields_free(hpack_field_t *f, int n);

#endif
