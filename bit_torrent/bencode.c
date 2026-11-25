/*
 * bencode.c - bencode 최소 파서 구현 (bencode.h 참고)
 */
#include <string.h>
#include "bencode.h"

#define BENCODE_MAX_DEPTH 16          /* 비정상 패킷의 과도한 중첩 방지 */

static int is_digit(uint8_t c) { return c >= '0' && c <= '9'; }

int bencode_str(const uint8_t *p, const uint8_t *end,
                const uint8_t **s, size_t *len, const uint8_t **next)
{
    size_t n = 0;
    int digits = 0;

    if (p >= end || !is_digit(*p)) return 0;
    while (p < end && is_digit(*p)) {
        if (++digits > 9) return 0;          /* 1GB 이상 길이는 비정상으로 간주 */
        n = n * 10 + (size_t)(*p - '0');
        p++;
    }
    if (p >= end || *p != ':') return 0;
    p++;
    if ((size_t)(end - p) < n) return 0;     /* 내용이 패킷 밖으로 나감 → 잘림 */
    if (s)    *s = p;
    if (len)  *len = n;
    if (next) *next = p + n;
    return 1;
}

int bencode_int(const uint8_t *p, const uint8_t *end, long long *v, const uint8_t **next)
{
    long long val = 0;
    int neg = 0, digits = 0;

    if (p >= end || *p != 'i') return 0;
    p++;
    if (p < end && *p == '-') { neg = 1; p++; }
    while (p < end && is_digit(*p)) {
        if (++digits > 18) return 0;
        val = val * 10 + (*p - '0');
        p++;
    }
    if (digits == 0 || p >= end || *p != 'e') return 0;
    if (v)    *v = neg ? -val : val;
    if (next) *next = p + 1;
    return 1;
}

const uint8_t *bencode_skip(const uint8_t *p, const uint8_t *end, int depth)
{
    const uint8_t *next;

    if (depth > BENCODE_MAX_DEPTH || p >= end) return NULL;

    if (*p == 'i')
        return bencode_int(p, end, NULL, &next) ? next : NULL;

    if (is_digit(*p))
        return bencode_str(p, end, NULL, NULL, &next) ? next : NULL;

    if (*p == 'l' || *p == 'd') {
        int is_dict = (*p == 'd');
        p++;
        while (p < end && *p != 'e') {
            if (is_dict) {                    /* 딕셔너리의 키는 반드시 문자열 */
                if (!bencode_str(p, end, NULL, NULL, &p)) return NULL;
            }
            p = bencode_skip(p, end, depth + 1);
            if (!p) return NULL;
        }
        if (p >= end) return NULL;            /* 닫는 'e' 가 없음 → 잘림 */
        return p + 1;
    }
    return NULL;
}

int bencode_dict_find(const uint8_t *p, const uint8_t *end, const char *key, const uint8_t **val)
{
    size_t klen = strlen(key);

    if (p >= end || *p != 'd') return 0;
    p++;
    while (p < end && *p != 'e') {
        const uint8_t *k;
        size_t kl;
        if (!bencode_str(p, end, &k, &kl, &p)) return 0;
        if (kl == klen && memcmp(k, key, klen) == 0) {
            if (val) *val = p;
            return 1;
        }
        p = bencode_skip(p, end, 1);          /* 원하는 키가 아니면 값을 건너뜀 */
        if (!p) return 0;
    }
    return 0;
}

int bencode_dict_str(const uint8_t *p, const uint8_t *end, const char *key,
                     const uint8_t **s, size_t *len)
{
    const uint8_t *v;
    if (!bencode_dict_find(p, end, key, &v)) return 0;
    return bencode_str(v, end, s, len, NULL);
}

int bencode_dict_int(const uint8_t *p, const uint8_t *end, const char *key, long long *v)
{
    const uint8_t *val;
    if (!bencode_dict_find(p, end, key, &val)) return 0;
    return bencode_int(val, end, v, NULL);
}
