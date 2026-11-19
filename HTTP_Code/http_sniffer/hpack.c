/* hpack.c - HPACK(RFC 7541) 디코더
 *  - 5.1 정수 표현 (prefix N비트)
 *  - 5.2 문자열 표현 (허프만 / 그대로)
 *  - 6.x 헤더 표현 4종 + 동적 테이블 크기 변경
 *  - 2.3 정적 테이블(1~61) + 동적 테이블(62~)
 */
#include <stdlib.h>
#include <string.h>
#include "hpack.h"
#include "hpack_tables.h"

#define STATIC_COUNT 61

void hpack_init(hpack_ctx_t *c)
{
    memset(c, 0, sizeof(*c));
    c->max_size = 4096;              /* SETTINGS_HEADER_TABLE_SIZE 기본값 */
}

static void entry_free(hpack_field_t *e) { free(e->name); free(e->value); e->name = e->value = NULL; }

void hpack_free(hpack_ctx_t *c)
{
    for (int i = 0; i < c->count; i++) entry_free(&c->dyn[i]);
    c->count = 0; c->size = 0;
}

void hpack_fields_free(hpack_field_t *f, int n)
{
    for (int i = 0; i < n; i++) entry_free(&f[i]);
}

/* 테이블 크기가 max_size 이하가 될 때까지 가장 오래된 항목부터 버린다 (4.4) */
static void evict(hpack_ctx_t *c, size_t limit)
{
    while (c->count > 0 && c->size > limit) {
        hpack_field_t *old = &c->dyn[c->count - 1];
        c->size -= strlen(old->name) + strlen(old->value) + 32;
        entry_free(old);
        c->count--;
    }
}

/* 동적 테이블에 새 항목 추가 (맨 앞 = 인덱스 62) */
static void dyn_add(hpack_ctx_t *c, const char *name, const char *value)
{
    size_t esz = strlen(name) + strlen(value) + 32;
    if (esz > c->max_size) { hpack_free(c); return; }   /* 너무 크면 테이블 비움 (4.4) */
    evict(c, c->max_size - esz);
    if (c->count == HPACK_MAX_DYN) {                     /* 항목 수 제한 (구현 한계) */
        c->size -= strlen(c->dyn[c->count - 1].name) + strlen(c->dyn[c->count - 1].value) + 32;
        entry_free(&c->dyn[c->count - 1]);
        c->count--;
    }
    memmove(&c->dyn[1], &c->dyn[0], sizeof(hpack_field_t) * c->count);
    c->dyn[0].name  = strdup(name);
    c->dyn[0].value = strdup(value);
    c->count++;
    c->size += esz;
}

/* 인덱스 -> (이름, 값). 없으면 0 */
static int lookup(hpack_ctx_t *c, uint64_t idx, const char **name, const char **value)
{
    if (idx == 0) return 0;
    if (idx <= STATIC_COUNT) {
        *name = STATIC_TABLE[idx][0]; *value = STATIC_TABLE[idx][1];
        return 1;
    }
    idx -= STATIC_COUNT + 1;
    if (idx >= (uint64_t)c->count) return 0;
    *name = c->dyn[idx].name; *value = c->dyn[idx].value;
    return 1;
}

/* 5.1 정수 디코딩. 반환: 읽은 바이트 수, 실패면 -1 */
static int dec_int(const uint8_t *p, const uint8_t *end, int prefix, uint64_t *out)
{
    if (p >= end) return -1;
    uint64_t max = (1u << prefix) - 1;
    uint64_t v = p[0] & max;
    int n = 1;
    if (v < max) { *out = v; return n; }
    int shift = 0;
    while (1) {
        if (p + n >= end || shift > 56) return -1;
        uint8_t b = p[n++];
        v += (uint64_t)(b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    *out = v;
    return n;
}

/* 부록 B 허프만 디코딩: 비트를 하나씩 쌓으면서 길이가 맞는 코드를 찾는다 */
static int huff_decode(const uint8_t *src, size_t len, char *dst, size_t cap)
{
    uint64_t cur = 0;
    int nbits = 0;
    size_t o = 0;

    for (size_t i = 0; i < len; i++) {
        cur = (cur << 8) | src[i];
        nbits += 8;
        while (nbits >= 5) {
            int found = 0;
            for (int L = 5; L <= 30 && L <= nbits && !found; L++) {
                uint32_t code = (uint32_t)((cur >> (nbits - L)) & ((1u << L) - 1));
                for (int s = 0; s < 256; s++) {
                    if (HUFF_LEN[s] == L && HUFF_CODE[s] == code) {
                        if (o + 1 < cap) dst[o++] = (char)s;
                        nbits -= L;
                        found = 1;
                        break;
                    }
                }
            }
            if (!found) {
                if (nbits >= 30) return -1;   /* 맞는 코드가 없음 (EOS 등) */
                break;                        /* 비트가 더 필요함 */
            }
        }
    }
    /* 남은 비트는 7비트 이하의 1로 된 패딩이어야 한다 (5.2) */
    if (nbits > 7) return -1;
    if (nbits > 0 && (cur & ((1u << nbits) - 1)) != (uint64_t)((1u << nbits) - 1)) return -1;
    dst[o] = '\0';
    return (int)o;
}

/* 5.2 문자열 디코딩. 반환: 읽은 바이트 수, 실패면 -1 */
static int dec_str(const uint8_t *p, const uint8_t *end, char *dst, size_t cap)
{
    uint64_t slen;
    if (p >= end) return -1;
    int huff = p[0] & 0x80;
    int n = dec_int(p, end, 7, &slen);
    if (n < 0 || slen > (uint64_t)(end - p - n)) return -1;
    if (huff) {
        if (huff_decode(p + n, (size_t)slen, dst, cap) < 0) return -1;
    } else {
        size_t k = slen < cap - 1 ? (size_t)slen : cap - 1;
        memcpy(dst, p + n, k);
        dst[k] = '\0';
    }
    return n + (int)slen;
}

static void emit(hpack_field_t *out, int *cnt, int max_out, const char *name, const char *value)
{
    if (*cnt >= max_out) return;
    out[*cnt].name  = strdup(name);
    out[*cnt].value = strdup(value);
    (*cnt)++;
}

int hpack_decode(hpack_ctx_t *c, const uint8_t *blk, size_t len,
                 hpack_field_t *out, int max_out)
{
    const uint8_t *p = blk, *end = blk + len;
    int cnt = 0;
    static char nbuf[HPACK_STR_MAX], vbuf[HPACK_STR_MAX];

    while (p < end) {
        uint8_t b = p[0];
        uint64_t idx;
        int n;
        const char *nm, *vl;

        if (b & 0x80) {                                  /* 6.1 인덱스 헤더 */
            if ((n = dec_int(p, end, 7, &idx)) < 0 || !lookup(c, idx, &nm, &vl)) goto fail;
            p += n;
            emit(out, &cnt, max_out, nm, vl);
        } else if ((b & 0xe0) == 0x20) {                 /* 6.3 동적 테이블 크기 변경 */
            if ((n = dec_int(p, end, 5, &idx)) < 0) goto fail;
            p += n;
            c->max_size = (size_t)idx;
            evict(c, c->max_size);
        } else {                                         /* 6.2 리터럴 3종 */
            int prefix, add;
            if ((b & 0xc0) == 0x40) { prefix = 6; add = 1; }   /* 증분 인덱싱 */
            else                    { prefix = 4; add = 0; }   /* 인덱싱 안 함 / 절대 안 함 */
            if ((n = dec_int(p, end, prefix, &idx)) < 0) goto fail;
            p += n;
            if (idx) {                                   /* 이름은 테이블에서 */
                if (!lookup(c, idx, &nm, &vl)) goto fail;
                strncpy(nbuf, nm, sizeof(nbuf) - 1); nbuf[sizeof(nbuf) - 1] = '\0';
            } else {                                     /* 이름도 문자열로 */
                if ((n = dec_str(p, end, nbuf, sizeof(nbuf))) < 0) goto fail;
                p += n;
            }
            if ((n = dec_str(p, end, vbuf, sizeof(vbuf))) < 0) goto fail;
            p += n;
            if (add) dyn_add(c, nbuf, vbuf);
            emit(out, &cnt, max_out, nbuf, vbuf);
        }
    }
    return cnt;

fail:
    hpack_fields_free(out, cnt);
    return -1;
}
