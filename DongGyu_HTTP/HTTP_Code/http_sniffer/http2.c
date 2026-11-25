/* http2.c - HTTP/2 프레임 파서 (RFC 9113)
 *  프레임 = [길이 3B][타입 1B][플래그 1B][R+스트림ID 4B] + 페이로드
 *  - 방향별 버퍼에 쌓고, 9+길이 만큼 모이면 프레임 하나씩 꺼낸다
 *  - HEADERS(+CONTINUATION) 블록이 END_HEADERS로 끝나면 HPACK 디코딩
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "http2.h"

const char H2_PREFACE[24] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#define F_END_STREAM  0x1
#define F_ACK         0x1
#define F_END_HEADERS 0x4
#define F_PADDED      0x8
#define F_PRIORITY    0x20

static uint32_t be24(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static const char *type_name(uint8_t t)
{
    static const char *n[] = { "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS",
                               "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION" };
    return t < 10 ? n[t] : "UNKNOWN";
}

static const char *setting_name(uint16_t id)
{
    switch (id) {
    case 1: return "HEADER_TABLE_SIZE";      case 2: return "ENABLE_PUSH";
    case 3: return "MAX_CONCURRENT_STREAMS"; case 4: return "INITIAL_WINDOW_SIZE";
    case 5: return "MAX_FRAME_SIZE";         case 6: return "MAX_HEADER_LIST_SIZE";
    default: return "?";
    }
}

int h2_is_preface(const uint8_t *p, size_t n)
{
    size_t k = n < sizeof(H2_PREFACE) ? n : sizeof(H2_PREFACE);
    return k >= 4 && memcmp(p, H2_PREFACE, k) == 0;
}

void h2_init(h2_dir_t *d)
{
    d->len = 0; d->preface_done = 0;
    d->hblen = 0; d->hcollect = 0;
    hpack_init(&d->hp);
}

void h2_reset(h2_dir_t *d)
{
    d->len = 0;
    d->hblen = 0; d->hcollect = 0;
}

void h2_free(h2_dir_t *d) { hpack_free(&d->hp); }

/* 헤더 블록 완성 -> HPACK 디코딩 후 출력 */
static void decode_headers(h2_dir_t *d, int dirn)
{
    hpack_field_t f[HPACK_MAX_FIELD];
    int n = hpack_decode(&d->hp, d->hblk, d->hblen, f, HPACK_MAX_FIELD);
    if (n < 0) {
        printf("      !! HPACK 디코딩 실패 (%zu bytes) — 캡처를 연결 중간부터 시작했을 수 있음\n", d->hblen);
        d->hblen = 0; d->hcollect = 0;
        return;
    }
    const char *method = "", *path = "", *auth = "", *status = "";
    for (int i = 0; i < n; i++) {
        if (!strcmp(f[i].name, ":method"))    method = f[i].value;
        if (!strcmp(f[i].name, ":path"))      path   = f[i].value;
        if (!strcmp(f[i].name, ":authority")) auth   = f[i].value;
        if (!strcmp(f[i].name, ":status"))    status = f[i].value;
    }
    if (status[0]) {
        printf("    [HTTP/2 응답 Response] stream=%u\n", d->hstream);
        printf("      Version     : HTTP/2\n");
        printf("      Status Code : %s\n", status);
    } else {
        printf("    [HTTP/2 요청 Request] stream=%u\n", d->hstream);
        printf("      Method      : %s\n", method);
        printf("      URI         : %s%s\n", auth, path);
        printf("      Version     : HTTP/2\n");
    }
    printf("      Headers (HPACK 디코딩 %zu bytes -> %d개):\n", d->hblen, n);
    for (int i = 0; i < n; i++) printf("        %s: %s\n", f[i].name, f[i].value);
    if (d->hend_stream) printf("      (END_STREAM: 본문 없음)\n");
    (void)dirn;
    hpack_fields_free(f, n);
    d->hblen = 0; d->hcollect = 0;
}

static void add_fragment(h2_dir_t *d, const uint8_t *p, size_t n)
{
    if (d->hblen + n > H2_HBLK) { printf("      !! 헤더 블록이 너무 큼\n"); d->hblen = 0; return; }
    memcpy(d->hblk + d->hblen, p, n);
    d->hblen += n;
}

static void print_frame(h2_dir_t *d, int dirn, const uint8_t *f)
{
    uint32_t len = be24(f);
    uint8_t type = f[3], flags = f[4];
    uint32_t sid = be32(f + 5) & 0x7fffffff;
    const uint8_t *pl = f + 9;

    printf("  [HTTP/2 Frame] %-13s len=%-5u stream=%-3u flags=0x%02x", type_name(type), len, sid, flags);
    if ((type == 0 || type == 1) && (flags & F_END_STREAM)) printf(" END_STREAM");
    if ((type == 1 || type == 5 || type == 9) && (flags & F_END_HEADERS)) printf(" END_HEADERS");
    if ((type == 4 || type == 6) && (flags & F_ACK)) printf(" ACK");
    putchar('\n');

    switch (type) {
    case 0: {                                           /* DATA */
        uint32_t pad = 0, off = 0;
        if (flags & F_PADDED) { pad = pl[0]; off = 1; }
        uint32_t dl = len >= off + pad ? len - off - pad : 0;
        printf("      data %u bytes: ", dl);
        for (uint32_t i = 0; i < dl && i < 80; i++) putchar(isprint(pl[off + i]) ? pl[off + i] : '.');
        if (dl > 80) printf(" ...");
        putchar('\n');
        break;
    }
    case 1: case 5: {                                   /* HEADERS / PUSH_PROMISE */
        uint32_t off = 0, pad = 0;
        if (flags & F_PADDED) { pad = pl[0]; off = 1; }
        if (type == 1 && (flags & F_PRIORITY)) off += 5;      /* 의존 스트림 4B + 가중치 1B */
        if (type == 5) off += 4;                              /* 약속된 스트림 ID */
        if (off + pad > len) { printf("      !! 잘못된 패딩\n"); break; }
        d->hstream = sid;
        d->hend_stream = type == 1 && (flags & F_END_STREAM);
        d->hblen = 0;
        add_fragment(d, pl + off, len - off - pad);
        d->hcollect = !(flags & F_END_HEADERS);
        if (!d->hcollect) decode_headers(d, dirn);
        else printf("      헤더 블록 조각 — CONTINUATION 대기\n");
        break;
    }
    case 9:                                             /* CONTINUATION */
        if (!d->hcollect) { printf("      !! 앞선 HEADERS 없이 온 CONTINUATION\n"); break; }
        add_fragment(d, pl, len);
        if (flags & F_END_HEADERS) decode_headers(d, dirn);
        break;
    case 3:                                             /* RST_STREAM */
        if (len >= 4) printf("      error code = %u\n", be32(pl));
        break;
    case 4:                                             /* SETTINGS */
        for (uint32_t i = 0; i + 6 <= len; i += 6)
            printf("      %s(%u) = %u\n", setting_name((uint16_t)(pl[i] << 8 | pl[i + 1])),
                   pl[i] << 8 | pl[i + 1], be32(pl + i + 2));
        break;
    case 7:                                             /* GOAWAY */
        if (len >= 8) printf("      last stream = %u, error code = %u\n", be32(pl) & 0x7fffffff, be32(pl + 4));
        break;
    case 8:                                             /* WINDOW_UPDATE */
        if (len >= 4) printf("      increment = %u\n", be32(pl) & 0x7fffffff);
        break;
    }
}

void h2_feed(h2_dir_t *d, int dirn, const uint8_t *p, size_t n)
{
    if (d->len + n > H2_BUF) {
        printf("  !! HTTP/2 재조립 버퍼 넘침 — 버퍼 초기화\n");
        h2_reset(d);
        if (n > H2_BUF) return;
    }
    memcpy(d->buf + d->len, p, n);
    d->len += n;

    size_t off = 0;
    if (dirn == 0 && !d->preface_done) {                /* 클라 첫 24바이트 */
        if (d->len < sizeof(H2_PREFACE)) return;
        if (memcmp(d->buf, H2_PREFACE, sizeof(H2_PREFACE)) == 0) {
            printf("  [HTTP/2] client connection preface (PRI * HTTP/2.0)\n");
            off = sizeof(H2_PREFACE);
        }
        d->preface_done = 1;
    }

    while (d->len - off >= 9) {                         /* 최소 프레임 헤더 9바이트 */
        uint32_t flen = be24(d->buf + off);
        if (d->len - off < 9 + flen) break;             /* 프레임 덜 옴 -> 다음 세그먼트 */
        print_frame(d, dirn, d->buf + off);
        off += 9 + flen;
    }
    if (off) {                                          /* 남은 조각을 앞으로 */
        memmove(d->buf, d->buf + off, d->len - off);
        d->len -= off;
    }
}
