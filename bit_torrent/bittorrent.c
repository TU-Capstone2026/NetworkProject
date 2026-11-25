/*
 * bittorrent.c - BitTorrent 응용 계층 분석 모듈 (류상진 담당)
 *
 * ┌──────────────────────────────────────────────────────────────────────┐
 * │ BitTorrent 통신 흐름                                                   │
 * │  1. 트래커(HTTP/UDP) 또는 DHT 로 "이 토렌트를 가진 피어 목록"을 얻는다    │
 * │  2. 피어와 TCP 연결 후 Peer Wire 핸드셰이크(68 bytes)를 주고받는다        │
 * │  3. bitfield / interested / unchoke / request / piece 메시지로 조각 교환 │
 * └──────────────────────────────────────────────────────────────────────┘
 *
 * 판별 방법: 포트 번호가 아니라 "내용(시그니처)"으로 판별한다.
 *   - 핸드셰이크 : 첫 바이트 19 + "BitTorrent protocol"
 *   - HTTP 트래커: "GET ...?info_hash=" / bencode 응답(interval, peers)
 *   - UDP 트래커 : connect 요청의 매직 번호 0x41727101980 + transaction_id 추적
 *   - DHT        : bencode 딕셔너리 + "y"(q/r/e), "t" 키
 *
 * Peer Wire 메시지는 [길이 4B][ID 1B][내용] 형식이라 TCP 세그먼트 경계와 맞지 않는다.
 * (예: 16KB piece 메시지가 여러 세그먼트에 나뉘어 옴)
 * → 연결(방향)별로 "다음 Seq"와 "현재 메시지의 남은 길이"를 기억해서 메시지 경계를 추적한다.
 */
#define _GNU_SOURCE            /* memmem */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "bittorrent.h"
#include "bencode.h"

#define BT_PSTR          "BitTorrent protocol"
#define BT_PSTR_LEN      19
#define BT_HS_LEN        68                    /* 1 + 19 + 8 + 20 + 20 */
#define BT_MAX_MSG       (2u * 1024u * 1024u)  /* 이보다 긴 메시지는 비정상으로 판단 */
#define MSG_ID_HANDSHAKE 255                   /* 내부용: 핸드셰이크 나머지 */
#define UDPT_MAGIC       0x41727101980ULL      /* UDP 트래커 connect 요청 고정값 */

#define MAX_STREAMS   512
#define MAX_SYNLOG    256
#define MAX_UDPT_TXN  64
#define MAX_UDPT_CONN 32
#define MAX_DHT_TXN   128

#define IND "       "      /* 상세 항목 들여쓰기 (" [APP] " 길이) */

/* ====================================================================== */
/* 설정 / 통계                                                              */
/* ====================================================================== */
static int      g_verbose;
static uint16_t g_ports[8];
static int      g_nports;

static struct {
    unsigned long handshakes, messages, keepalive;
    unsigned long msg_by_id[22];        /* 0~20, 21 = 그 외 */
    unsigned long cont_segments, retrans, resync;
    unsigned long tcp_setup, tcp_teardown, not_plain;
    unsigned long http_tracker, udp_tracker;
    unsigned long dht_query, dht_resp, dht_err;
} st;

void bt_init(int verbose, const uint16_t *ports, int nports)
{
    g_verbose = verbose;
    g_nports = nports > 8 ? 8 : nports;
    for (int i = 0; i < g_nports; i++) g_ports[i] = ports[i];
}

/* BitTorrent 에서 흔히 쓰는 포트(6881~6889) 또는 -p 로 지정한 포트인지 */
static int is_bt_port(uint16_t port)
{
    if (port >= 6881 && port <= 6889) return 1;
    for (int i = 0; i < g_nports; i++)
        if (g_ports[i] == port) return 1;
    return 0;
}

/* ====================================================================== */
/* 공통 도우미                                                              */
/* ====================================================================== */
static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t rd64(const uint8_t *p) { return ((uint64_t)rd32(p) << 32) | rd32(p + 4); }

static void print_hex(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

/* 출력 가능한 문자는 그대로, 나머지는 \xHH */
static void print_escaped(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (p[i] >= 0x20 && p[i] < 0x7f && p[i] != '\\') putchar(p[i]);
        else printf("\\x%02x", p[i]);
    }
}

/* 압축(compact) 피어 형식 6 bytes = IPv4(4) + Port(2) */
static void print_compact_peer(const uint8_t *p)
{
    printf("%u.%u.%u.%u:%u", p[0], p[1], p[2], p[3], rd16(p + 4));
}

/* 출력 헤더를 필요할 때 한 번만 찍기 위한 상태 */
struct out_ctx {
    const struct pkt_info *pi;
    const char *title;
    int printed;
};

static void out_header(struct out_ctx *o)
{
    if (!o->printed) {
        print_pkt_header(o->pi, o->title);
        o->printed = 1;
    }
}

/* ====================================================================== */
/* TCP 스트림(한 방향) 상태 테이블                                            */
/* ====================================================================== */
struct bt_stream {
    int      used;
    uint32_t src, dst;
    uint16_t sport, dport;
    uint8_t  cap_dir;        /* 송신/수신 (lo 에서는 같은 패킷이 두 번 잡히므로 구분) */
    int      is_bt;          /* 이 방향에서 핸드셰이크 확인 */
    int      checked;        /* BT 포트인데 평문 핸드셰이크가 아님을 이미 알림 */
    int      synced;         /* 메시지 경계를 알고 있음 */
    uint32_t next_seq;       /* 다음에 와야 할 Sequence Number */
    uint32_t skip;           /* 현재 메시지에서 아직 안 온 바이트 수 */
    uint8_t  cur_id;         /* 현재 이어지고 있는 메시지 ID */
    uint8_t  hbuf[24];       /* 세그먼트 경계에 걸친 메시지 헤더 임시 저장 */
    uint32_t hlen;
    int      fin_sent;       /* 이 방향에서 FIN 을 보냄 */
    uint32_t fin_ack;        /* 그 FIN 에 대한 ACK 번호 */
    int      fin_acks;       /* 출력한 FIN-ACK 수 */
    unsigned long last;      /* 마지막 사용 시점(패킷 번호) - 테이블 교체 기준 */
};
static struct bt_stream g_streams[MAX_STREAMS];

static int tuple_eq(const struct bt_stream *s, uint32_t a, uint16_t ap, uint32_t b, uint16_t bp)
{
    return s->src == a && s->sport == ap && s->dst == b && s->dport == bp;
}

static struct bt_stream *stream_find(const struct pkt_info *pi, int create)
{
    struct bt_stream *victim = NULL;

    for (int i = 0; i < MAX_STREAMS; i++) {
        struct bt_stream *s = &g_streams[i];
        if (s->used && s->cap_dir == pi->dir &&
            tuple_eq(s, pi->src_addr, pi->src_port, pi->dst_addr, pi->dst_port)) {
            s->last = pi->pkt_no;
            return s;
        }
        if (!create) continue;
        /* 빈 칸 우선, 없으면 가장 오래 안 쓴 칸 */
        if (!victim) victim = s;
        else if (victim->used && (!s->used || s->last < victim->last)) victim = s;
    }
    if (!create) return NULL;

    memset(victim, 0, sizeof *victim);
    victim->used    = 1;
    victim->src     = pi->src_addr;
    victim->dst     = pi->dst_addr;
    victim->sport   = pi->src_port;
    victim->dport   = pi->dst_port;
    victim->cap_dir = (uint8_t)pi->dir;
    victim->last    = pi->pkt_no;
    return victim;
}

/* 이 연결(양방향 중 어느 쪽이든)이 BitTorrent 로 확인됐는지 */
static int flow_is_bt(const struct pkt_info *pi)
{
    for (int i = 0; i < MAX_STREAMS; i++) {
        const struct bt_stream *s = &g_streams[i];
        if (!s->used || !s->is_bt) continue;
        if (tuple_eq(s, pi->src_addr, pi->src_port, pi->dst_addr, pi->dst_port) ||
            tuple_eq(s, pi->dst_addr, pi->dst_port, pi->src_addr, pi->src_port))
            return 1;
    }
    return 0;
}

/* 이 연결에 대해 "평문 핸드셰이크 아님"을 이미 알렸는지 (양방향 중 한 번만 출력) */
static int flow_checked(const struct pkt_info *pi)
{
    for (int i = 0; i < MAX_STREAMS; i++) {
        const struct bt_stream *s = &g_streams[i];
        if (!s->used || !s->checked) continue;
        if (tuple_eq(s, pi->src_addr, pi->src_port, pi->dst_addr, pi->dst_port) ||
            tuple_eq(s, pi->dst_addr, pi->dst_port, pi->src_addr, pi->src_port))
            return 1;
    }
    return 0;
}

/* 반대 방향에서 보낸 FIN 중, 이 패킷이 ACK 하는 것 */
static struct bt_stream *find_fin_acked(const struct pkt_info *pi)
{
    for (int i = 0; i < MAX_STREAMS; i++) {
        struct bt_stream *s = &g_streams[i];
        if (s->used && s->fin_sent && s->fin_ack == pi->ack &&
            tuple_eq(s, pi->dst_addr, pi->dst_port, pi->src_addr, pi->src_port))
            return s;
    }
    return NULL;
}

/* ====================================================================== */
/* TCP 연결 설정(3-way handshake) 기록                                       */
/*   SYN 시점에는 BitTorrent 인지 알 수 없으므로 모든 SYN 을 저장해 두었다가,    */
/*   핸드셰이크로 BitTorrent 가 확인되면 그 연결의 SYN/SYN+ACK/ACK 를 출력한다.  */
/* ====================================================================== */
struct syn_entry {
    int      used, printed;
    unsigned long pkt_no;
    struct timeval ts;
    enum pkt_dir dir;
    uint32_t src, dst;
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t  flags;
};
static struct syn_entry g_synlog[MAX_SYNLOG];
static int g_synpos;

static void synlog_add(const struct pkt_info *pi)
{
    struct syn_entry *e = &g_synlog[g_synpos];
    g_synpos = (g_synpos + 1) % MAX_SYNLOG;
    e->used = 1; e->printed = 0;
    e->pkt_no = pi->pkt_no; e->ts = pi->ts; e->dir = pi->dir;
    e->src = pi->src_addr; e->dst = pi->dst_addr;
    e->sport = pi->src_port; e->dport = pi->dst_port;
    e->seq = pi->seq; e->ack = pi->ack; e->flags = pi->tcp_flags;
}

/* 순수 ACK 가 3-way handshake 의 3단계인지 (SYN+ACK 의 Seq+1 을 ACK) */
static void synlog_maybe_third(const struct pkt_info *pi)
{
    for (int i = 0; i < MAX_SYNLOG; i++) {
        const struct syn_entry *e = &g_synlog[i];
        if (e->used && (e->flags & (TF_SYN | TF_ACK)) == (TF_SYN | TF_ACK) &&
            e->src == pi->dst_addr && e->sport == pi->dst_port &&
            e->dst == pi->src_addr && e->dport == pi->src_port &&
            pi->ack == e->seq + 1 && pi->seq == e->ack) {
            synlog_add(pi);
            return;
        }
    }
}

static void print_conn_setup(const struct pkt_info *pi)
{
    int found = 0;
    char tb[32], fb[40];

    for (int k = 0; k < MAX_SYNLOG; k++) {        /* 오래된 것부터 = 시간순 */
        struct syn_entry *e = &g_synlog[(g_synpos + k) % MAX_SYNLOG];
        if (!e->used || e->printed) continue;
        int fwd = e->src == pi->src_addr && e->sport == pi->src_port &&
                  e->dst == pi->dst_addr && e->dport == pi->dst_port;
        int rev = e->src == pi->dst_addr && e->sport == pi->dst_port &&
                  e->dst == pi->src_addr && e->dport == pi->src_port;
        if (!fwd && !rev) continue;

        if (!found) {
            printf(" [TCP 연결 설정] 이 연결의 3-way handshake (앞서 캡처된 패킷)\n");
            found = 1;
        }
        const char *step =
            (e->flags & TF_SYN) && (e->flags & TF_ACK) ? "2단계 SYN+ACK: 연결 요청 수락" :
            (e->flags & TF_SYN)                         ? "1단계 SYN: 연결 요청" :
                                                          "3단계 ACK: 연결 확립";
        printf(IND "#%lu [%s] [%s] %u -> %u  Flags=[%s]  Seq=%u",
               e->pkt_no, time_str(&e->ts, tb, sizeof tb), dir_str(e->dir),
               e->sport, e->dport, tcp_flags_str(e->flags, fb, sizeof fb), e->seq);
        if (e->flags & TF_ACK) printf("  Ack=%u", e->ack);
        printf("  (%s)\n", step);
        e->printed = 1;
    }
    if (found) st.tcp_setup++;
}

/* ====================================================================== */
/* Peer Wire 핸드셰이크                                                      */
/*   [pstrlen=19][ "BitTorrent protocol" ][reserved 8][info_hash 20][peer_id 20] */
/* ====================================================================== */

/* Peer ID 앞부분으로 클라이언트 추정 (Azureus 형식: -XX1234-) */
static void describe_client(const uint8_t *pid, char *out, size_t outsz)
{
    static const struct { const char *code; const char *name; } az[] = {
        { "qB", "qBittorrent" },      { "TR", "Transmission" },
        { "UT", "uTorrent" },         { "UM", "uTorrent Mac" },
        { "LT", "libtorrent (Rasterbar)" }, { "lt", "libTorrent (Rakshasa)" },
        { "DE", "Deluge" },           { "AZ", "Vuze (Azureus)" },
        { "BI", "BiglyBT" },          { "BC", "BitComet" },
        { "KT", "KTorrent" },         { "WW", "WebTorrent" },
        { "BT", "BitTorrent (Mainline)" }, { "FD", "Free Download Manager" },
    };

    if (pid[0] == '-' && pid[7] == '-') {
        const char *name = NULL;
        for (size_t i = 0; i < sizeof az / sizeof az[0]; i++)
            if (pid[1] == az[i].code[0] && pid[2] == az[i].code[1]) { name = az[i].name; break; }
        char ver[16];
        snprintf(ver, sizeof ver, "%c.%c.%c.%c", pid[3], pid[4], pid[5], pid[6]);
        if (name) snprintf(out, outsz, "%s (버전 코드 %s)", name, ver);
        else      snprintf(out, outsz, "알 수 없는 클라이언트 코드 '%c%c' (버전 코드 %s)",
                           pid[1], pid[2], ver);
    } else if (memcmp(pid, "A2-", 3) == 0) {
        snprintf(out, outsz, "aria2");
    } else if (pid[0] == 'M' && pid[1] >= '0' && pid[1] <= '9') {
        snprintf(out, outsz, "BitTorrent Mainline (구버전 형식)");
    } else {
        snprintf(out, outsz, "알 수 없음 (표준 형식 아님)");
    }
}

/* 핸드셰이크 출력. 해석에 사용한 바이트 수 반환 (잘렸으면 n) */
static size_t print_handshake(const uint8_t *p, size_t n)
{
    printf(" [APP] BitTorrent Handshake\n");
    printf(IND "pstrlen    : %u\n", p[0]);
    printf(IND "pstr       : \"%s\"\n", BT_PSTR);
    if (n < 28) { printf(IND "(나머지는 다음 세그먼트에 있음)\n"); return n; }

    const uint8_t *r = p + 20;
    printf(IND "Reserved   : %02x %02x %02x %02x %02x %02x %02x %02x  →",
           r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
    int any = 0;
    if (r[5] & 0x10) { printf(" [Extension Protocol(BEP 10)]"); any = 1; }
    if (r[7] & 0x04) { printf(" [Fast Extension(BEP 6)]"); any = 1; }
    if (r[7] & 0x01) { printf(" [DHT(BEP 5)]"); any = 1; }
    if (!any) printf(" 확장 기능 표시 없음");
    printf("\n");

    if (n < 48) { printf(IND "(Info Hash 이후는 다음 세그먼트에 있음)\n"); return n; }
    printf(IND "Info Hash  : ");
    print_hex(p + 28, 20);
    printf("  (토렌트 식별값, info 딕셔너리의 SHA-1)\n");

    if (n < BT_HS_LEN) { printf(IND "(Peer ID 는 다음 세그먼트에 있음)\n"); return n; }
    printf(IND "Peer ID    : ");
    print_escaped(p + 48, 20);
    printf("\n");
    char client[96];
    describe_client(p + 48, client, sizeof client);
    printf(IND "Client     : %s\n", client);
    return BT_HS_LEN;
}

/* ====================================================================== */
/* Peer Wire 메시지   [length 4B][id 1B][payload]   (length = id + payload) */
/* ====================================================================== */
static const char *msg_name(int id)
{
    switch (id) {
    case 0:  return "Choke";
    case 1:  return "Unchoke";
    case 2:  return "Interested";
    case 3:  return "Not Interested";
    case 4:  return "Have";
    case 5:  return "Bitfield";
    case 6:  return "Request";
    case 7:  return "Piece";
    case 8:  return "Cancel";
    case 9:  return "Port";
    case 13: return "Suggest Piece";
    case 14: return "Have All";
    case 15: return "Have None";
    case 16: return "Reject Request";
    case 17: return "Allowed Fast";
    case 20: return "Extended";
    case MSG_ID_HANDSHAKE: return "Handshake";
    default: return "Unknown";
    }
}

static const char *msg_desc(int id)
{
    switch (id) {
    case 0:  return "상대에게 업로드하지 않겠음(차단)";
    case 1:  return "상대에게 업로드 허용(차단 해제)";
    case 2:  return "상대가 가진 조각을 받고 싶음";
    case 3:  return "상대 조각에 관심 없음";
    case 4:  return "조각 하나를 새로 다 받았음을 알림";
    case 5:  return "내가 가진 조각 목록(비트맵)";
    case 6:  return "블록 데이터 요청";
    case 7:  return "요청한 블록 데이터 전송";
    case 8:  return "보낸 요청 취소";
    case 9:  return "내 DHT 포트 알림";
    case 13: return "이 조각을 먼저 받아 가라고 제안 (BEP 6)";
    case 14: return "모든 조각 보유 (BEP 6)";
    case 15: return "보유 조각 없음 (BEP 6)";
    case 16: return "요청 거절 (BEP 6)";
    case 17: return "choke 상태에서도 받을 수 있는 조각 (BEP 6)";
    case 20: return "확장 메시지 (BEP 10)";
    default: return "표준에 없는 메시지 ID";
    }
}

/* ID 뒤에 오는 고정 길이 필드 크기 (이만큼은 모아서 한 번에 해석) */
static uint32_t fixed_len(int id)
{
    switch (id) {
    case 4: case 13: case 17: return 4;            /* piece index */
    case 6: case 8: case 16:  return 12;           /* index, begin, length */
    case 7:                   return 8;            /* index, begin (+ 블록 데이터) */
    case 9:                   return 2;            /* port */
    case 20:                  return 1;            /* 확장 메시지 ID */
    default:                  return 0;
    }
}

/* 표준 길이와 맞는지 */
static int length_ok(int id, uint32_t mlen)
{
    switch (id) {
    case 0: case 1: case 2: case 3: case 14: case 15: return mlen == 1;
    case 4: case 13: case 17: return mlen == 5;
    case 6: case 8: case 16:  return mlen == 13;
    case 9:                   return mlen == 3;
    case 7:                   return mlen >= 9;
    case 5:                   return mlen >= 2;
    case 20:                  return mlen >= 2;
    default:                  return 1;
    }
}

/* 표준에 있는 ID 인지 (경계를 잃었을 때 재탐색용) */
static int known_id(int id)
{
    return (id >= 0 && id <= 9) || (id >= 13 && id <= 17) || id == 20;
}

/* 세그먼트 시작이 메시지 시작처럼 보이는지 (경계를 잃은 뒤 다시 찾을 때) */
static int looks_like_msg_start(const uint8_t *p, size_t n)
{
    if (n < 5) return 0;
    uint32_t mlen = rd32(p);
    int id = p[4];
    if (mlen == 0 || mlen > BT_MAX_MSG || !known_id(id)) return 0;
    if (!length_ok(id, mlen)) return 0;
    if (id == 7 && mlen > 9 + 131072) return 0;     /* 블록은 보통 16KB, 최대 128KB */
    return 1;
}

static void print_bitfield(const uint8_t *b, size_t avail, uint32_t total)
{
    unsigned long ones = 0;
    for (size_t i = 0; i < avail; i++) ones += (unsigned long)__builtin_popcount(b[i]);

    printf(IND "Bitfield   : %u bytes (조각 최대 %u개 표현, 1=보유 0=미보유)\n", total, total * 8);
    if (avail == total) printf(IND "보유 조각  : %lu개\n", ones);
    else printf(IND "보유 조각  : 캡처된 %zu bytes 기준 %lu개 (나머지는 다음 세그먼트)\n", avail, ones);
    if (avail > 0) {
        printf(IND "앞부분     :");
        for (size_t i = 0; i < avail && i < 4; i++) {
            printf(" ");
            for (int bit = 7; bit >= 0; bit--) putchar((b[i] >> bit) & 1 ? '1' : '0');
        }
        printf("%s\n", avail > 4 ? " ..." : "");
    }
}

/* Extended 메시지 (BEP 10). ext_id 0 = 확장 핸드셰이크(bencode 딕셔너리) */
static void print_extended(uint8_t ext_id, uint32_t mlen, const uint8_t *body,
                           size_t avail, uint32_t body_left)
{
    if (ext_id != 0) {
        printf(IND "확장 ID    : %u (확장 핸드셰이크에서 협상한 번호), 데이터 %u bytes\n",
               ext_id, mlen - 2);
        return;
    }
    printf(IND "확장 ID    : 0 → Extended Handshake (지원하는 확장 기능 목록 교환)\n");
    if (avail < body_left)
        printf(IND "(본문 %zu/%u bytes 만 이 세그먼트에 있음 → 일부만 해석)\n", avail, body_left);

    const uint8_t *end = body + avail, *m, *s;
    size_t sl;
    long long v;

    if (bencode_dict_find(body, end, "m", &m) && m < end && *m == 'd') {
        printf(IND "m (확장)   :");
        const uint8_t *q = m + 1;
        while (q < end && *q != 'e') {
            const uint8_t *k;
            size_t kl;
            long long num;
            if (!bencode_str(q, end, &k, &kl, &q)) break;
            if (bencode_int(q, end, &num, &q)) printf(" %.*s=%lld", (int)kl, k, num);
            else if (!(q = bencode_skip(q, end, 1))) break;
        }
        printf("\n");
    }
    if (bencode_dict_str(body, end, "v", &s, &sl)) {
        printf(IND "v (클라이언트): ");
        print_escaped(s, sl);
        printf("\n");
    }
    if (bencode_dict_int(body, end, "p", &v))             printf(IND "p (리슨 포트): %lld\n", v);
    if (bencode_dict_int(body, end, "metadata_size", &v)) printf(IND "metadata_size: %lld bytes\n", v);
    if (bencode_dict_int(body, end, "reqq", &v))          printf(IND "reqq (최대 요청 수): %lld\n", v);
    if (bencode_dict_str(body, end, "yourip", &s, &sl) && sl == 4)
        printf(IND "yourip (상대가 본 내 IP): %u.%u.%u.%u\n", s[0], s[1], s[2], s[3]);
}

/* 메시지 하나 출력. h = [length][id][고정 필드] */
static void print_message(const uint8_t *h, uint32_t mlen, int id,
                          const uint8_t *body, size_t avail, uint32_t body_left)
{
    printf(" [APP] BitTorrent Message: %s (id=%d, len=%u) - %s\n", msg_name(id), id, mlen, msg_desc(id));
    if (!length_ok(id, mlen)) printf(IND "※ 표준 길이와 다름\n");

    switch (id) {
    case 4: case 13: case 17:
        if (mlen >= 5) printf(IND "Piece Index: %u\n", rd32(h + 5));
        break;
    case 6: case 8: case 16:
        if (mlen >= 13)
            printf(IND "Index=%u  Begin=%u  Length=%u\n", rd32(h + 5), rd32(h + 9), rd32(h + 13));
        break;
    case 7:
        if (mlen >= 9)
            printf(IND "Index=%u  Begin=%u  블록 크기=%u bytes (이 세그먼트에 %zu bytes)\n",
                   rd32(h + 5), rd32(h + 9), mlen - 9, avail);
        break;
    case 9:
        if (mlen >= 3) printf(IND "DHT Port   : %u\n", rd16(h + 5));
        break;
    case 5:
        print_bitfield(body, avail, mlen - 1);
        break;
    case 20:
        if (mlen >= 2) print_extended(h[5], mlen, body, avail, body_left);
        break;
    default:
        break;
    }
}

/* 헤더 버퍼에 want 바이트가 찰 때까지 데이터를 옮김 */
static int collect(struct bt_stream *s, const uint8_t **p, size_t *n, uint32_t want)
{
    while (s->hlen < want && *n > 0) {
        s->hbuf[s->hlen++] = **p;
        (*p)++;
        (*n)--;
    }
    return s->hlen >= want;
}

/* 한 세그먼트 안의 메시지들을 순서대로 해석 */
static void parse_messages(struct bt_stream *s, struct out_ctx *o, const uint8_t *p, size_t n)
{
    uint32_t carried = s->hlen;     /* 이전 세그먼트에서 넘어온 헤더 조각 */
    uint32_t lead_cont = 0;         /* 세그먼트 앞부분이 이전 메시지의 데이터인 경우 */
    uint8_t  lead_id = 0;
    uint32_t lead_left = 0;
    int first = 1;
    size_t seg_len = n;

    while (n > 0) {
        /* (1) 이전 메시지(예: piece 블록)의 나머지 데이터 */
        if (s->skip > 0) {
            uint32_t k = s->skip < n ? s->skip : (uint32_t)n;
            s->skip -= k;
            if (g_verbose || o->printed) {
                out_header(o);
                printf(" [APP] (이어짐) 이전 %s 메시지 데이터 %u bytes, 남은 %u bytes\n",
                       msg_name(s->cur_id), k, s->skip);
            } else if (first) {
                lead_cont = k; lead_id = s->cur_id; lead_left = s->skip;
            }
            p += k; n -= k;
            first = 0;
            continue;
        }

        /* (2) 길이 4 bytes */
        if (!collect(s, &p, &n, 4)) break;
        uint32_t mlen = rd32(s->hbuf);

        if (lead_cont) {        /* 새 메시지가 시작되므로 앞부분 이어짐도 함께 출력 */
            out_header(o);
            printf(" [APP] (이어짐) 이전 %s 메시지 데이터 %u bytes, 남은 %u bytes\n",
                   msg_name(lead_id), lead_cont, lead_left);
            lead_cont = 0;
        }

        if (mlen == 0) {
            out_header(o);
            printf(" [APP] BitTorrent Message: Keep-Alive (len=0) - 연결 유지 확인\n");
            st.keepalive++;
            s->hlen = 0; carried = 0;
            first = 0;
            continue;
        }
        if (mlen > BT_MAX_MSG) {
            out_header(o);
            printf(" [APP] 비정상 메시지 길이 %u → 이 연결의 메시지 경계 추적 중단\n", mlen);
            s->synced = 0; s->hlen = 0; s->skip = 0;
            return;
        }

        /* (3) ID + 고정 필드 */
        if (!collect(s, &p, &n, 5)) break;
        int id = s->hbuf[4];
        uint32_t need = 5 + fixed_len(id);
        if (need > 4 + mlen) need = 4 + mlen;
        if (!collect(s, &p, &n, need)) break;

        uint32_t body_left = 4 + mlen - need;
        size_t avail = body_left < n ? body_left : n;

        out_header(o);
        print_message(s->hbuf, mlen, id, p, avail, body_left);
        if (carried) {
            printf(IND "(앞의 %u bytes 는 이전 세그먼트에 있던 것을 합쳐서 해석)\n", carried);
            carried = 0;
        }
        st.messages++;
        st.msg_by_id[id <= 20 ? id : 21]++;

        s->cur_id = (uint8_t)id;
        s->hlen = 0;
        p += avail; n -= avail;
        s->skip = body_left - (uint32_t)avail;
        if (s->skip) printf(IND "→ 나머지 %u bytes 는 다음 세그먼트로 이어짐\n", s->skip);
        first = 0;
    }

    /* 세그먼트가 메시지 헤더 중간에서 끝남 */
    if (s->hlen > 0 && s->hlen != carried) {
        out_header(o);
        printf(" [APP] 메시지 헤더 일부(%u bytes)만 도착 → 다음 세그먼트와 합쳐서 해석\n", s->hlen);
    }
    /* 세그먼트 전체가 이전 메시지의 데이터 (출력 생략, 통계만) */
    if (!o->printed && lead_cont == seg_len) st.cont_segments++;
}

/* ====================================================================== */
/* BitTorrent 연결의 제어 패킷 (FIN / RST / ACK)                              */
/* ====================================================================== */
static void note_fin_rst(const struct pkt_info *pi, struct out_ctx *o)
{
    uint8_t f = pi->tcp_flags;

    if (f & TF_RST) {
        o->title = "BitTorrent TCP 연결 해제 (RST)";
        out_header(o);
        printf(" [TCP 연결 해제] RST: 연결 강제 종료\n");
        st.tcp_teardown++;
        return;
    }
    if (f & TF_FIN) {
        struct bt_stream *self = stream_find(pi, 1);
        int acks_peer_fin = find_fin_acked(pi) != NULL;
        self->is_bt = 1;
        self->fin_sent = 1;
        self->fin_ack = pi->seq + (uint32_t)pi->payload_len + 1;   /* FIN 은 Seq 1 소비 */
        o->title = "BitTorrent TCP 연결 해제 (FIN)";
        out_header(o);
        printf(" [TCP 연결 해제] FIN: 이 방향의 데이터 전송 종료%s\n",
               acks_peer_fin ? " + 상대 FIN 에 대한 ACK" : "");
        st.tcp_teardown++;
    }
}

static int handle_ctrl(const struct pkt_info *pi, struct out_ctx *o)
{
    if (pi->tcp_flags & (TF_FIN | TF_RST)) {
        note_fin_rst(pi, o);
        return 1;
    }
    struct bt_stream *fin_owner = find_fin_acked(pi);
    if (fin_owner && fin_owner->fin_acks < 2) {     /* lo 에서는 같은 ACK 가 두 번 잡힘 */
        fin_owner->fin_acks++;
        o->title = "BitTorrent TCP 연결 해제 (ACK)";
        out_header(o);
        printf(" [TCP 연결 해제] ACK: 상대가 보낸 FIN 확인 (Ack=%u)\n", pi->ack);
        return 1;
    }
    if (g_verbose) {
        o->title = "BitTorrent (순수 ACK)";
        out_header(o);
        return 1;
    }
    return 0;
}

/* ====================================================================== */
/* 이미 핸드셰이크가 확인된 스트림의 데이터 세그먼트                             */
/* ====================================================================== */
static int handle_bt_stream(struct bt_stream *s, const struct pkt_info *pi, struct out_ctx *o)
{
    const uint8_t *p = pi->payload;
    size_t n = pi->payload_len;
    uint32_t seq = pi->seq;

    if (n == 0) return handle_ctrl(pi, o);

    if (s->synced) {
        int32_t diff = (int32_t)(seq - s->next_seq);
        if (diff < 0) {
            uint32_t dup = (uint32_t)(-diff);
            if (dup >= n) {                       /* 이미 분석한 구간을 다시 받음 */
                st.retrans++;
                if (g_verbose) {
                    o->title = "BitTorrent Peer Wire (재전송)";
                    out_header(o);
                    printf(" [APP] 재전송 세그먼트 - 이미 분석한 데이터 %zu bytes\n", n);
                }
                goto ctrl;
            }
            p += dup; n -= dup; seq += dup;       /* 일부만 겹치면 새 부분만 분석 */
        } else if (diff > 0) {                    /* 중간 세그먼트를 못 받음 */
            out_header(o);
            printf(" [APP] 앞선 데이터 %d bytes 를 캡처하지 못함 → 메시지 경계 다시 찾기\n", diff);
            s->synced = 0; s->skip = 0; s->hlen = 0;
        }
    }

    if (!s->synced) {
        if (!looks_like_msg_start(p, n)) {
            s->next_seq = seq + (uint32_t)n;
            if (g_verbose || o->printed) {
                out_header(o);
                printf(" [APP] 메시지 경계를 찾는 중 (데이터 %zu bytes 건너뜀)\n", n);
            }
            goto ctrl;
        }
        s->synced = 1; s->skip = 0; s->hlen = 0;
        st.resync++;
        out_header(o);
        printf(" [APP] 메시지 경계 다시 찾음\n");
    }

    s->next_seq = seq + (uint32_t)n;
    parse_messages(s, o, p, n);

ctrl:
    if (pi->tcp_flags & (TF_FIN | TF_RST)) note_fin_rst(pi, o);
    return o->printed;
}

/* ====================================================================== */
/* HTTP 트래커                                                               */
/*   GET /announce?info_hash=..&peer_id=..&port=..&uploaded=..&left=.. HTTP/1.1 */
/*   응답 본문: d8:intervali1800e5:peers<6*N bytes>e  (bencode)                */
/* ====================================================================== */
static size_t url_decode(const uint8_t *s, size_t n, uint8_t *out, size_t outmax)
{
    size_t o = 0;
    for (size_t i = 0; i < n && o < outmax; i++) {
        if (s[i] == '%' && i + 2 < n) {
            char hx[3] = { (char)s[i + 1], (char)s[i + 2], 0 };
            char *endp;
            long v = strtol(hx, &endp, 16);
            if (*endp == '\0') { out[o++] = (uint8_t)v; i += 2; continue; }
        }
        out[o++] = s[i] == '+' ? ' ' : s[i];
    }
    return o;
}

static int is_http_tracker_request(const uint8_t *p, size_t n)
{
    if (n < 16 || memcmp(p, "GET ", 4) != 0) return 0;
    const uint8_t *le = memchr(p, '\n', n);
    size_t line_len = le ? (size_t)(le - p) : n;
    return memmem(p, line_len, "info_hash=", 10) != NULL;
}

static void print_http_tracker_request(const struct pkt_info *pi, const uint8_t *p, size_t n)
{
    const uint8_t *le = memchr(p, '\n', n);
    size_t line_len = le ? (size_t)(le - p) : n;
    if (line_len && p[line_len - 1] == '\r') line_len--;

    const uint8_t *path = p + 4;
    const uint8_t *line_end = p + line_len;
    const uint8_t *q = memchr(path, '?', (size_t)(line_end - path));
    const uint8_t *qend = q ? memchr(q, ' ', (size_t)(line_end - q)) : NULL;
    if (!qend) qend = line_end;
    size_t path_len = q ? (size_t)(q - path) : 0;
    int is_scrape = path_len && memmem(path, path_len, "scrape", 6);

    print_pkt_header(pi, is_scrape ? "BitTorrent HTTP Tracker - Scrape 요청"
                                   : "BitTorrent HTTP Tracker - Announce 요청");
    printf(" [APP] HTTP Tracker %s 요청: GET %.*s\n",
           is_scrape ? "Scrape" : "Announce", (int)path_len, path);

    /* 쿼리 파라미터를 하나씩 해석 */
    const uint8_t *cur = q ? q + 1 : qend;
    while (cur < qend) {
        const uint8_t *amp = memchr(cur, '&', (size_t)(qend - cur));
        const uint8_t *pend = amp ? amp : qend;
        const uint8_t *eq = memchr(cur, '=', (size_t)(pend - cur));
        if (eq) {
            size_t kl = (size_t)(eq - cur);
            const uint8_t *val = eq + 1;
            size_t vl = (size_t)(pend - val);
            uint8_t dec[128];
            size_t dl = url_decode(val, vl, dec, sizeof dec);

            if (kl == 9 && memcmp(cur, "info_hash", 9) == 0) {
                printf(IND "info_hash  : ");
                if (dl == 20) print_hex(dec, 20); else print_escaped(dec, dl);
                printf("\n");
            } else if (kl == 7 && memcmp(cur, "peer_id", 7) == 0) {
                printf(IND "peer_id    : ");
                print_escaped(dec, dl);
                if (dl == 20) {
                    char client[96];
                    describe_client(dec, client, sizeof client);
                    printf("  (%s)", client);
                }
                printf("\n");
            } else {
                const char *desc = "";
                if      (kl == 4  && !memcmp(cur, "port", 4))        desc = "  (피어 연결을 받을 포트)";
                else if (kl == 8  && !memcmp(cur, "uploaded", 8))    desc = "  (지금까지 업로드한 bytes)";
                else if (kl == 10 && !memcmp(cur, "downloaded", 10)) desc = "  (지금까지 다운로드한 bytes)";
                else if (kl == 4  && !memcmp(cur, "left", 4))        desc = "  (남은 bytes)";
                else if (kl == 5  && !memcmp(cur, "event", 5))       desc = "  (started/completed/stopped)";
                else if (kl == 7  && !memcmp(cur, "compact", 7))     desc = "  (1 = 피어 목록을 6 bytes 압축 형식으로)";
                else if (kl == 7  && !memcmp(cur, "numwant", 7))     desc = "  (받고 싶은 피어 수)";
                printf(IND "%-11.*s: ", (int)kl, cur);
                print_escaped(dec, dl);
                printf("%s\n", desc);
            }
        }
        cur = amp ? amp + 1 : qend;
    }

    /* Host 헤더 */
    const uint8_t *host = memmem(p, n, "\r\nHost:", 7);
    if (host) {
        host += 7;
        while (host < p + n && *host == ' ') host++;
        const uint8_t *he = memmem(host, (size_t)(p + n - host), "\r\n", 2);
        if (he) printf(IND "Host       : %.*s\n", (int)(he - host), host);
    }
    st.http_tracker++;
}

static int find_http_body(const uint8_t *p, size_t n, const uint8_t **body, size_t *blen)
{
    const uint8_t *e = memmem(p, n, "\r\n\r\n", 4);
    if (!e) return 0;
    *body = e + 4;
    *blen = n - (size_t)(*body - p);
    /* chunked 전송이면 첫 줄(청크 크기)을 건너뜀 */
    if (memmem(p, (size_t)(e - p), "chunked", 7)) {
        size_t look = *blen < 12 ? *blen : 12;
        const uint8_t *crlf = memmem(*body, look, "\r\n", 2);
        if (crlf) {
            *blen -= (size_t)(crlf + 2 - *body);
            *body = crlf + 2;
        }
    }
    return 1;
}

static int is_http_tracker_response(const uint8_t *p, size_t n)
{
    const uint8_t *body;
    size_t blen;
    if (n < 12 || memcmp(p, "HTTP/1.", 7) != 0) return 0;
    if (!find_http_body(p, n, &body, &blen) || blen < 2 || body[0] != 'd') return 0;
    const uint8_t *end = body + blen;
    return bencode_dict_find(body, end, "interval", NULL) ||
           bencode_dict_find(body, end, "failure reason", NULL) ||
           bencode_dict_find(body, end, "peers", NULL);
}

static void print_http_tracker_response(const struct pkt_info *pi, const uint8_t *p, size_t n)
{
    const uint8_t *body, *s, *v;
    size_t blen, sl;
    long long num;

    find_http_body(p, n, &body, &blen);
    const uint8_t *end = body + blen;
    const uint8_t *le = memmem(p, n, "\r\n", 2);

    print_pkt_header(pi, "BitTorrent HTTP Tracker - 응답");
    printf(" [APP] HTTP Tracker 응답: %.*s (본문은 bencode 딕셔너리)\n",
           le ? (int)(le - p) : 0, p);

    if (bencode_dict_str(body, end, "failure reason", &s, &sl)) {
        printf(IND "failure reason: ");
        print_escaped(s, sl);
        printf("\n");
    }
    if (bencode_dict_int(body, end, "interval", &num))     printf(IND "interval   : %lld 초 (다음 announce 까지 대기)\n", num);
    if (bencode_dict_int(body, end, "min interval", &num)) printf(IND "min interval: %lld 초\n", num);
    if (bencode_dict_int(body, end, "complete", &num))     printf(IND "complete   : %lld (시더 수)\n", num);
    if (bencode_dict_int(body, end, "incomplete", &num))   printf(IND "incomplete : %lld (리처 수)\n", num);

    if (bencode_dict_find(body, end, "peers", &v)) {
        if (bencode_str(v, end, &s, &sl, NULL)) {           /* compact 형식 */
            printf(IND "peers      : %zu개 (compact, 6 bytes 씩)", sl / 6);
            for (size_t i = 0; i + 6 <= sl && i < 6 * 5; i += 6) {
                printf(i ? ", " : " → ");
                print_compact_peer(s + i);
            }
            printf("%s\n", sl / 6 > 5 ? " ..." : "");
        } else if (v < end && *v == 'l') {                  /* 딕셔너리 리스트 형식 */
            int cnt = 0;
            const uint8_t *q = v + 1;
            printf(IND "peers      : (딕셔너리 형식)");
            while (q && q < end && *q != 'e') {
                const uint8_t *ip;
                size_t il;
                long long port;
                const uint8_t *nx = bencode_skip(q, end, 1);
                if (!nx) break;
                if (cnt < 5 && bencode_dict_str(q, nx, "ip", &ip, &il) &&
                    bencode_dict_int(q, nx, "port", &port))
                    printf("%s%.*s:%lld", cnt ? ", " : " ", (int)il, ip, port);
                cnt++;
                q = nx;
            }
            printf("  (총 %d개)\n", cnt);
        }
    }
    if (bencode_dict_str(body, end, "peers6", &s, &sl))
        printf(IND "peers6     : %zu개 (IPv6, 18 bytes 씩)\n", sl / 18);
    st.http_tracker++;
}

/* ====================================================================== */
/* UDP 트래커 (BEP 15)                                                       */
/*   요청: [connection_id 8][action 4][transaction_id 4] ...                 */
/*   응답: [action 4][transaction_id 4] ...                                  */
/*   action: 0=connect 1=announce 2=scrape 3=error                           */
/* ====================================================================== */
struct udpt_txn { int used; uint32_t tid; uint32_t action; };
static struct udpt_txn g_udpt_txn[MAX_UDPT_TXN];
static int g_udpt_txn_pos;
static uint64_t g_udpt_conn[MAX_UDPT_CONN];
static int g_udpt_conn_pos;

static const char *udpt_action(uint32_t a)
{
    switch (a) {
    case 0: return "connect";
    case 1: return "announce";
    case 2: return "scrape";
    case 3: return "error";
    default: return "?";
    }
}

static const char *udpt_event(uint32_t e)
{
    switch (e) {
    case 0: return "none";
    case 1: return "completed (다운로드 완료)";
    case 2: return "started (다운로드 시작)";
    case 3: return "stopped (중지)";
    default: return "?";
    }
}

static void udpt_txn_add(uint32_t tid, uint32_t action)
{
    g_udpt_txn[g_udpt_txn_pos].used = 1;
    g_udpt_txn[g_udpt_txn_pos].tid = tid;
    g_udpt_txn[g_udpt_txn_pos].action = action;
    g_udpt_txn_pos = (g_udpt_txn_pos + 1) % MAX_UDPT_TXN;
}

/* 요청에서 본 transaction_id 인지. 찾으면 요청 action 반환, 없으면 -1 */
static int udpt_txn_find(uint32_t tid)
{
    for (int i = 0; i < MAX_UDPT_TXN; i++)
        if (g_udpt_txn[i].used && g_udpt_txn[i].tid == tid) return (int)g_udpt_txn[i].action;
    return -1;
}

static void udpt_conn_add(uint64_t cid)
{
    g_udpt_conn[g_udpt_conn_pos] = cid;
    g_udpt_conn_pos = (g_udpt_conn_pos + 1) % MAX_UDPT_CONN;
}

static int udpt_conn_known(uint64_t cid)
{
    for (int i = 0; i < MAX_UDPT_CONN; i++)
        if (cid != 0 && g_udpt_conn[i] == cid) return 1;
    return 0;
}

static int try_udp_tracker(const struct pkt_info *pi)
{
    const uint8_t *p = pi->payload;
    size_t n = pi->payload_len;
    if (n < 8) return 0;

    /* ---------- 요청 ---------- */
    if (n >= 16) {
        uint64_t cid = rd64(p);
        uint32_t act = rd32(p + 8), tid = rd32(p + 12);
        int is_req =
            (act == 0 && cid == UDPT_MAGIC) ||
            (act == 1 && n >= 98 && rd32(p + 80) <= 3 && (n == 98 || udpt_conn_known(cid))) ||
            (act == 2 && n >= 36 && (n - 16) % 20 == 0 && udpt_conn_known(cid));
        if (is_req) {
            char title[80];
            snprintf(title, sizeof title, "BitTorrent UDP Tracker - %s 요청", udpt_action(act));
            print_pkt_header(pi, title);
            printf(" [APP] UDP Tracker 요청 (BEP 15): action=%u (%s)\n", act, udpt_action(act));
            printf(IND "Connection ID  : 0x%016llx%s\n", (unsigned long long)cid,
                   act == 0 ? " (connect 고정값 0x41727101980)" :
                   udpt_conn_known(cid) ? " (connect 응답으로 받은 값)" :
                                          " (캡처한 connect 응답에 없던 값)");
            printf(IND "Transaction ID : 0x%08x (%u)\n", tid, tid);
            if (act == 1) {
                printf(IND "Info Hash      : "); print_hex(p + 16, 20); printf("\n");
                printf(IND "Peer ID        : "); print_escaped(p + 36, 20);
                char client[96];
                describe_client(p + 36, client, sizeof client);
                printf("  (%s)\n", client);
                printf(IND "Downloaded=%llu  Left=%llu  Uploaded=%llu\n",
                       (unsigned long long)rd64(p + 56), (unsigned long long)rd64(p + 64),
                       (unsigned long long)rd64(p + 72));
                printf(IND "Event          : %u (%s)\n", rd32(p + 80), udpt_event(rd32(p + 80)));
                printf(IND "Num Want       : %d   Port : %u\n", (int32_t)rd32(p + 92), rd16(p + 96));
            } else if (act == 2) {
                for (size_t off = 16; off + 20 <= n; off += 20) {
                    printf(IND "Info Hash      : ");
                    print_hex(p + off, 20);
                    printf("\n");
                }
            }
            udpt_txn_add(tid, act);
            return 1;
        }
    }

    /* ---------- 응답 ---------- */
    uint32_t act = rd32(p), tid = rd32(p + 4);
    int req_act = udpt_txn_find(tid);
    if (act > 3 || req_act < 0) return 0;
    if (act != 3 && (uint32_t)req_act != act) return 0;

    char title[80];
    snprintf(title, sizeof title, "BitTorrent UDP Tracker - %s 응답", udpt_action(act));
    print_pkt_header(pi, title);
    printf(" [APP] UDP Tracker 응답 (BEP 15): action=%u (%s)\n", act, udpt_action(act));
    printf(IND "Transaction ID : 0x%08x (%u) - 요청과 일치\n", tid, tid);

    if (act == 0 && n >= 16) {
        uint64_t cid = rd64(p + 8);
        printf(IND "Connection ID  : 0x%016llx (이후 announce/scrape 요청에 사용)\n",
               (unsigned long long)cid);
        udpt_conn_add(cid);
    } else if (act == 1 && n >= 20) {
        size_t peers = (n - 20) / 6;
        printf(IND "Interval=%u초  Leechers=%u  Seeders=%u\n", rd32(p + 8), rd32(p + 12), rd32(p + 16));
        printf(IND "Peers          : %zu개", peers);
        for (size_t i = 0; i < peers && i < 5; i++) {
            printf(i ? ", " : " → ");
            print_compact_peer(p + 20 + i * 6);
        }
        printf("%s\n", peers > 5 ? " ..." : "");
    } else if (act == 2) {
        for (size_t off = 8; off + 12 <= n; off += 12)
            printf(IND "Seeders=%u  Completed=%u  Leechers=%u\n",
                   rd32(p + off), rd32(p + off + 4), rd32(p + off + 8));
    } else if (act == 3) {
        printf(IND "Error Message  : ");
        print_escaped(p + 8, n - 8);
        printf("\n");
    }
    return 1;
}

/* ====================================================================== */
/* Mainline DHT (BEP 5) - KRPC 메시지 (UDP 위의 bencode 딕셔너리)              */
/*   t: transaction ID, y: q(질의)/r(응답)/e(오류), q: 메서드, a/r: 인자/결과    */
/* ====================================================================== */
struct dht_txn { int used; uint8_t tid[8]; size_t tlen; char method[24]; };
static struct dht_txn g_dht_txn[MAX_DHT_TXN];
static int g_dht_pos;

static void dht_txn_add(const uint8_t *t, size_t tl, const uint8_t *m, size_t ml)
{
    struct dht_txn *e = &g_dht_txn[g_dht_pos];
    g_dht_pos = (g_dht_pos + 1) % MAX_DHT_TXN;
    if (tl > sizeof e->tid) tl = sizeof e->tid;
    if (ml >= sizeof e->method) ml = sizeof e->method - 1;
    e->used = 1;
    memcpy(e->tid, t, tl);
    e->tlen = tl;
    memcpy(e->method, m, ml);
    e->method[ml] = '\0';
}

static const char *dht_txn_method(const uint8_t *t, size_t tl)
{
    /* 가장 최근 것부터 검색 */
    for (int k = 1; k <= MAX_DHT_TXN; k++) {
        const struct dht_txn *e = &g_dht_txn[(g_dht_pos - k + MAX_DHT_TXN) % MAX_DHT_TXN];
        if (e->used && e->tlen == tl && memcmp(e->tid, t, tl) == 0) return e->method;
    }
    return NULL;
}

static const char *dht_method_desc(const uint8_t *m, size_t ml)
{
    if (ml == 4  && !memcmp(m, "ping", 4))          return "노드가 살아 있는지 확인";
    if (ml == 9  && !memcmp(m, "find_node", 9))     return "목표 ID 에 가까운 노드 찾기";
    if (ml == 9  && !memcmp(m, "get_peers", 9))     return "이 info_hash 를 가진 피어 찾기";
    if (ml == 13 && !memcmp(m, "announce_peer", 13)) return "내가 이 토렌트를 받고 있음을 등록";
    if (ml == 17 && !memcmp(m, "sample_infohashes", 17)) return "노드가 가진 info_hash 샘플 요청 (BEP 51)";
    return "기타 메서드";
}

static void print_id_line(const char *label, const uint8_t *s, size_t sl)
{
    printf(IND "%-15s: ", label);
    print_hex(s, sl);
    printf("\n");
}

/* Transaction ID: hex 로 출력하고, 글자로 읽을 수 있으면 함께 표시 (예: 6161 "aa") */
static void print_tid_line(const uint8_t *t, size_t tl)
{
    int printable = tl > 0;
    for (size_t i = 0; i < tl; i++)
        if (t[i] < 0x20 || t[i] >= 0x7f) printable = 0;
    printf(IND "%-15s: ", "Transaction ID");
    print_hex(t, tl);
    if (printable) printf(" (\"%.*s\")", (int)tl, t);
    printf("\n");
}

/* a 또는 r 딕셔너리 안의 공통 필드 */
static void print_dht_args(const uint8_t *d, const uint8_t *end)
{
    const uint8_t *s, *v;
    size_t sl;
    long long num;

    if (bencode_dict_str(d, end, "id", &s, &sl))        print_id_line("Node ID", s, sl);
    if (bencode_dict_str(d, end, "info_hash", &s, &sl)) print_id_line("Info Hash", s, sl);
    if (bencode_dict_str(d, end, "target", &s, &sl))    print_id_line("Target", s, sl);
    if (bencode_dict_int(d, end, "port", &num))         printf(IND "%-15s: %lld\n", "Port", num);
    if (bencode_dict_int(d, end, "implied_port", &num))
        printf(IND "%-15s: %lld (1 이면 UDP 출발지 포트를 대신 사용)\n", "implied_port", num);
    if (bencode_dict_str(d, end, "token", &s, &sl))     print_id_line("Token", s, sl);

    if (bencode_dict_str(d, end, "nodes", &s, &sl)) {   /* 노드 26 bytes = ID 20 + IP 4 + Port 2 */
        printf(IND "%-15s: %zu개 (26 bytes 씩)", "Nodes", sl / 26);
        for (size_t i = 0; i + 26 <= sl && i < 26 * 3; i += 26) {
            printf(i ? ", " : " → ");
            print_compact_peer(s + i + 20);
        }
        printf("%s\n", sl / 26 > 3 ? " ..." : "");
    }
    if (bencode_dict_find(d, end, "values", &v) && v < end && *v == 'l') {
        int cnt = 0;
        const uint8_t *q = v + 1;
        printf(IND "%-15s:", "Values (피어)");
        while (q < end && *q != 'e') {
            const uint8_t *ps;
            size_t pl;
            if (!bencode_str(q, end, &ps, &pl, &q)) break;
            if (pl == 6 && cnt < 5) { printf(cnt ? ", " : " "); print_compact_peer(ps); }
            cnt++;
        }
        printf("  (총 %d개)\n", cnt);
    }
}

static int try_dht(const struct pkt_info *pi)
{
    const uint8_t *p = pi->payload;
    size_t n = pi->payload_len;
    const uint8_t *end = p + n;
    const uint8_t *y, *t, *s, *v;
    size_t yl, tl, sl;

    if (n < 12 || p[0] != 'd' || p[n - 1] != 'e') return 0;
    if (bencode_skip(p, end, 0) != end) return 0;          /* 전체가 딕셔너리 하나인지 */
    if (!bencode_dict_str(p, end, "y", &y, &yl) || yl != 1) return 0;
    if (!bencode_dict_str(p, end, "t", &t, &tl)) return 0;
    if (y[0] != 'q' && y[0] != 'r' && y[0] != 'e') return 0;

    if (y[0] == 'q') {
        const uint8_t *m;
        size_t ml;
        if (!bencode_dict_str(p, end, "q", &m, &ml)) return 0;
        char title[96];
        snprintf(title, sizeof title, "BitTorrent DHT - %.*s 질의", (int)(ml < 40 ? ml : 40), m);
        print_pkt_header(pi, title);
        printf(" [APP] DHT Query (BEP 5): y=q  q=%.*s - %s\n", (int)ml, m, dht_method_desc(m, ml));
        print_tid_line(t, tl);
        if (bencode_dict_find(p, end, "a", &v)) print_dht_args(v, end);
        dht_txn_add(t, tl, m, ml);
        st.dht_query++;
    } else if (y[0] == 'r') {
        const char *method = dht_txn_method(t, tl);
        print_pkt_header(pi, "BitTorrent DHT - 응답");
        if (method) printf(" [APP] DHT Response (BEP 5): y=r - %s 질의에 대한 응답 (Transaction ID 로 매칭)\n", method);
        else        printf(" [APP] DHT Response (BEP 5): y=r\n");
        print_tid_line(t, tl);
        if (bencode_dict_find(p, end, "r", &v)) print_dht_args(v, end);
        st.dht_resp++;
    } else {
        print_pkt_header(pi, "BitTorrent DHT - 오류");
        printf(" [APP] DHT Error (BEP 5): y=e\n");
        print_tid_line(t, tl);
        if (bencode_dict_find(p, end, "e", &v) && *v == 'l') {
            long long code;
            const uint8_t *q = v + 1;
            if (bencode_int(q, end, &code, &q)) {
                printf(IND "%-15s: %lld\n", "Error Code", code);
                if (bencode_str(q, end, &s, &sl, NULL)) {
                    printf(IND "%-15s: ", "Error Message");
                    print_escaped(s, sl);
                    printf("\n");
                }
            }
        }
        st.dht_err++;
    }

    /* 공통 선택 필드 */
    if (bencode_dict_str(p, end, "v", &s, &sl)) {
        printf(IND "%-15s: ", "v (클라이언트)");
        print_escaped(s, sl);
        printf("\n");
    }
    if (bencode_dict_str(p, end, "ip", &s, &sl) && sl == 6) {
        printf(IND "%-15s: ", "ip (상대가 본 내 주소)");
        print_compact_peer(s);
        printf("\n");
    }
    return 1;
}

/* ====================================================================== */
/* 진입점                                                                    */
/* ====================================================================== */
int bt_analyze_tcp(const struct pkt_info *pi)
{
    const uint8_t *p = pi->payload;
    size_t n = pi->payload_len;
    uint8_t f = pi->tcp_flags;
    struct out_ctx o = { pi, "BitTorrent Peer Wire", 0 };

    /* (0) 연결 설정 패킷은 일단 기록만 (BitTorrent 인지는 핸드셰이크에서 확인) */
    if (f & TF_SYN) synlog_add(pi);
    else if (n == 0 && (f & (TF_ACK | TF_FIN | TF_RST)) == TF_ACK) synlog_maybe_third(pi);

    /* (1) Peer Wire 핸드셰이크 */
    if (n >= 1 + BT_PSTR_LEN && p[0] == BT_PSTR_LEN && memcmp(p + 1, BT_PSTR, BT_PSTR_LEN) == 0) {
        struct bt_stream *s = stream_find(pi, 1);
        o.title = "BitTorrent Peer Wire - Handshake";
        out_header(&o);
        print_conn_setup(pi);
        size_t used = print_handshake(p, n);
        st.handshakes++;

        s->is_bt = 1; s->synced = 1; s->hlen = 0; s->skip = 0;
        if (used < BT_HS_LEN) {           /* 핸드셰이크가 다음 세그먼트까지 이어짐 */
            s->skip = BT_HS_LEN - (uint32_t)used;
            s->cur_id = MSG_ID_HANDSHAKE;
        }
        s->next_seq = pi->seq + (uint32_t)n;
        if (used < n) {                    /* 같은 세그먼트에 붙어 온 메시지들 */
            parse_messages(s, &o, p + used, n - used);
        }
        if (f & (TF_FIN | TF_RST)) note_fin_rst(pi, &o);
        return 1;
    }

    /* (2) HTTP 트래커 */
    if (is_http_tracker_request(p, n))  { print_http_tracker_request(pi, p, n);  return 1; }
    if (is_http_tracker_response(p, n)) { print_http_tracker_response(pi, p, n); return 1; }

    /* (3) 핸드셰이크로 확인된 스트림 */
    struct bt_stream *s = stream_find(pi, 0);
    if (s && s->is_bt) return handle_bt_stream(s, pi, &o);

    /* (4) 반대 방향만 확인된 연결의 제어 패킷 (FIN / RST / ACK) */
    if (n == 0 && (flow_is_bt(pi) || find_fin_acked(pi)))
        return handle_ctrl(pi, &o);

    /* (5) BitTorrent 포트인데 첫 데이터가 평문 핸드셰이크가 아님 → 암호화 연결 가능성 */
    if (n > 0 && (is_bt_port(pi->src_port) || is_bt_port(pi->dst_port)) &&
        !flow_is_bt(pi) && !flow_checked(pi)) {
        struct bt_stream *c = stream_find(pi, 1);
        c->checked = 1;
        o.title = "BitTorrent 포트 - 평문 핸드셰이크 아님";
        out_header(&o);
        print_conn_setup(pi);
        printf(" [APP] BitTorrent 포트(%u/%u)의 첫 데이터가 \"\\x13BitTorrent protocol\" 로 시작하지 않음\n",
               pi->src_port, pi->dst_port);
        printf(IND "→ 암호화(MSE/PE) 연결이거나 다른 프로토콜일 수 있음. 앞 16 bytes: ");
        print_hex(p, n < 16 ? n : 16);
        printf("\n");
        st.not_plain++;
        return 1;
    }
    return 0;
}

int bt_analyze_udp(const struct pkt_info *pi)
{
    if (try_udp_tracker(pi)) { st.udp_tracker++; return 1; }
    if (try_dht(pi)) return 1;
    return 0;
}

void bt_print_stats(void)
{
    static const int ids[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 14, 15, 16, 17, 20 };

    printf("---------------- BitTorrent 분석 통계 ----------------\n");
    printf(" Peer Wire 핸드셰이크 : %lu\n", st.handshakes);
    printf(" Peer Wire 메시지     : %lu (Keep-Alive %lu 별도)\n", st.messages, st.keepalive);
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++)
        if (st.msg_by_id[ids[i]])
            printf("   - %-15s : %lu\n", msg_name(ids[i]), st.msg_by_id[ids[i]]);
    if (st.msg_by_id[21]) printf("   - %-15s : %lu\n", "Unknown", st.msg_by_id[21]);
    printf(" 데이터만 이어진 세그먼트 : %lu (piece 블록 등, -v 로 출력)\n", st.cont_segments);
    printf(" 재전송 / 경계 재탐색 : %lu / %lu\n", st.retrans, st.resync);
    printf(" TCP 연결 설정 / 해제 : %lu / %lu\n", st.tcp_setup, st.tcp_teardown);
    printf(" 평문 아닌 BT 포트 연결: %lu\n", st.not_plain);
    printf(" HTTP 트래커          : %lu\n", st.http_tracker);
    printf(" UDP 트래커           : %lu\n", st.udp_tracker);
    printf(" DHT 질의/응답/오류   : %lu / %lu / %lu\n", st.dht_query, st.dht_resp, st.dht_err);
}
