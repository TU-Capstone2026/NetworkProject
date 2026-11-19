/* main.c - 미니 Wireshark: raw socket HTTP 스니퍼 (HTTP/1.0 · 1.1 · 2 통합)
 *
 *  사용법:  sudo ./http_sniffer <인터페이스> [HTTP 포트 ...]
 *           예) sudo ./http_sniffer eth0            (기본 포트 80 8080 8000)
 *               sudo ./http_sniffer eth0 -v         (데이터 없는 ACK도 출력)
 *
 *  처리 흐름
 *   1) raw socket(AF_PACKET)으로 송신·수신 프레임 캡처
 *   2) Ethernet 헤더 -> EtherType 0x0800(IPv4)만
 *   3) IP 헤더 -> 프로토콜 번호 6(TCP) / 17(UDP)
 *   4) TCP/UDP 헤더 -> 포트, Seq/Ack/플래그  (UDP는 53번 DNS만 헤더 요약)
 *   5) TCP 연결별 seq 추적 (중복 제거, 누락 경고)
 *   6) HTTP 버전 판별 -> 파서 분기 (역다중화)
 *        "PRI * HTTP/2.0" 로 시작  -> HTTP/2 (프레임 재조립 + HPACK)
 *        "GET / POST / HTTP/1."     -> HTTP/1.0·1.1 (텍스트 파싱)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "http1.h"
#include "http2.h"

#define MAX_CONN  32
#define MAX_PORTS 8
#define SNAPLEN   65536

enum { P_UNKNOWN, P_HTTP1, P_HTTP2 };

typedef struct {
    int       init;
    uint32_t  next_seq;
    int       fin;
    h1_dir_t  h1;
    h2_dir_t  h2;
} dir_t;

typedef struct {
    int       used;
    int       id;
    uint32_t  cip, sip;     /* 클라 / 서버 IP (network order) */
    uint16_t  cport, sport; /* host order */
    int       proto;
    int       req_head;     /* 마지막 HTTP/1 요청이 HEAD였는지 */
    dir_t     d[2];         /* d[0] = 클라->서버, d[1] = 서버->클라 */
} conn_t;

static conn_t   conns[MAX_CONN];
static int      conn_seq;
static uint16_t ports[MAX_PORTS];
static int      nports;
static int      verbose;
static volatile sig_atomic_t stop;
static unsigned long pkt_no;

static void on_sigint(int s) { (void)s; stop = 1; }

static int is_http_port(uint16_t p)
{
    for (int i = 0; i < nports; i++) if (ports[i] == p) return 1;
    return 0;
}

static const char *ip_str(uint32_t a, char *buf)
{
    struct in_addr in = { .s_addr = a };
    return inet_ntop(AF_INET, &in, buf, INET_ADDRSTRLEN);
}

static void flags_str(const struct tcphdr *t, char *out)
{
    out[0] = '\0';
    if (t->syn) strcat(out, "SYN,");
    if (t->fin) strcat(out, "FIN,");
    if (t->rst) strcat(out, "RST,");
    if (t->psh) strcat(out, "PSH,");
    if (t->ack) strcat(out, "ACK,");
    if (t->urg) strcat(out, "URG,");
    size_t n = strlen(out);
    if (n) out[n - 1] = '\0';
}

/* ── 연결 테이블 ── */
static void conn_free(conn_t *c)
{
    h2_free(&c->d[0].h2);
    h2_free(&c->d[1].h2);
    memset(c, 0, sizeof(*c));
}

static conn_t *conn_get(uint32_t cip, uint16_t cport, uint32_t sip, uint16_t sport, int create)
{
    conn_t *empty = NULL;
    for (int i = 0; i < MAX_CONN; i++) {
        conn_t *c = &conns[i];
        if (c->used && c->cip == cip && c->sip == sip && c->cport == cport && c->sport == sport) return c;
        if (!c->used && !empty) empty = c;
    }
    if (!create) return NULL;
    if (!empty) {                                    /* 꽉 차면 0번 재사용 */
        printf("  !! 연결 테이블 가득 참 — 가장 앞 연결 정리\n");
        conn_free(&conns[0]);
        empty = &conns[0];
    }
    memset(empty, 0, sizeof(*empty));
    empty->used = 1;
    empty->id = ++conn_seq;
    empty->cip = cip; empty->sip = sip; empty->cport = cport; empty->sport = sport;
    for (int k = 0; k < 2; k++) { h1_reset(&empty->d[k].h1); h2_init(&empty->d[k].h2); }
    return empty;
}

/* ── 6) HTTP 버전 판별 -> 파서 분기 ── */
static void dispatch_http(conn_t *c, int dirn, const uint8_t *p, size_t n)
{
    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];

    if (c->proto == P_UNKNOWN) {
        if (dirn == 0 && h2_is_preface(p, n))      c->proto = P_HTTP2;
        else if (looks_like_http1(p, n))           c->proto = P_HTTP1;
        if (c->proto != P_UNKNOWN)
            printf("  ▶ 연결 #%d %s:%u <-> %s:%u  버전 판별: %s\n", c->id,
                   ip_str(c->cip, a), c->cport, ip_str(c->sip, b), c->sport,
                   c->proto == P_HTTP2 ? "HTTP/2 (connection preface 감지)"
                                       : "HTTP/1.x (텍스트 시작줄 감지)");
    }

    switch (c->proto) {
    case P_HTTP2: h2_feed(&c->d[dirn].h2, dirn, p, n); break;
    case P_HTTP1: h1_feed(&c->d[dirn].h1, dirn, p, n, &c->req_head); break;
    default:      printf("  [?] HTTP로 판별되지 않은 데이터 %zu bytes\n", n); break;
    }
}

/* ── 4~5) TCP 처리 ── */
static void print_eth(const struct ethhdr *e)
{
    printf(" Ethernet : %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x  type=0x%04x (IPv4)\n",
           e->h_source[0], e->h_source[1], e->h_source[2], e->h_source[3], e->h_source[4], e->h_source[5],
           e->h_dest[0], e->h_dest[1], e->h_dest[2], e->h_dest[3], e->h_dest[4], e->h_dest[5], ntohs(e->h_proto));
}

static void handle_tcp(const struct ethhdr *eth, const struct iphdr *ip, const uint8_t *seg, size_t seglen,
                       const char *dir_label, const char *ts)
{
    if (seglen < sizeof(struct tcphdr)) return;
    const struct tcphdr *t = (const struct tcphdr *)seg;
    size_t thl = t->doff * 4u;
    if (thl < 20 || thl > seglen) return;

    uint16_t sp = ntohs(t->source), dp = ntohs(t->dest);
    if (!is_http_port(sp) && !is_http_port(dp)) return;

    const uint8_t *pl = seg + thl;
    size_t plen = seglen - thl;
    uint32_t seq = ntohl(t->seq), ack = ntohl(t->ack_seq);

    /* 클라/서버 방향 정하기: 목적지 포트가 HTTP 포트면 클라->서버 */
    int dirn = is_http_port(dp) ? 0 : 1;
    uint32_t cip = dirn == 0 ? ip->saddr : ip->daddr, sip = dirn == 0 ? ip->daddr : ip->saddr;
    uint16_t cport = dirn == 0 ? sp : dp, sport = dirn == 0 ? dp : sp;

    int interesting = plen > 0 || t->syn || t->fin || t->rst;
    if (!interesting && !verbose) return;

    conn_t *c = conn_get(cip, cport, sip, sport, plen > 0 || t->syn);
    dir_t *d = c ? &c->d[dirn] : NULL;

    /* 5) seq 추적: 재전송·중복 제거, 누락(gap) 감지 */
    const char *note = "";
    if (d && plen > 0) {
        if (!d->init) { d->init = 1; d->next_seq = seq; }
        int32_t diff = (int32_t)(seq - d->next_seq);
        if ((int32_t)(seq + plen - d->next_seq) <= 0) {
            /* 이미 본 데이터 (재전송 / lo 중복 캡처) */
            if (verbose) printf("  (중복 세그먼트 seq=%u len=%zu — 건너뜀)\n", seq, plen);
            return;
        }
        if (diff < 0) {                              /* 앞부분만 겹침 -> 잘라냄 */
            pl += -diff; plen -= (size_t)-diff;
        } else if (diff > 0) {
            note = "  !! TCP gap (데이터 누락)";
            h2_reset(&d->h2);
            h1_reset(&d->h1);
        }
        d->next_seq = (diff < 0 ? seq + (uint32_t)-diff : seq) + (uint32_t)plen;
    } else if (d && t->syn) {
        d->init = 1; d->next_seq = seq + 1;
    }

    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN], fl[40];
    flags_str(t, fl);
    printf("\n──── #%lu %s %s ────\n", pkt_no, ts, dir_label);
    print_eth(eth);
    printf(" IPv4     : %s -> %s  ttl=%u  total_len=%u  id=%u  proto=6 (TCP)\n",
           ip_str(ip->saddr, a), ip_str(ip->daddr, b), ip->ttl, ntohs(ip->tot_len), ntohs(ip->id));
    printf(" TCP      : %u -> %u  seq=%u  ack=%u  flags=[%s]  win=%u  payload=%zu%s\n",
           sp, dp, seq, ack, fl, ntohs(t->window), plen, note);

    if (t->syn && !t->ack) printf("  ▷ 연결 설정 1단계 (SYN)\n");
    else if (t->syn)       printf("  ▷ 연결 설정 2단계 (SYN-ACK)\n");

    if (c && plen > 0) dispatch_http(c, dirn, pl, plen);

    if (t->fin || t->rst) {
        printf("  ▷ %s\n", t->rst ? "연결 강제 종료 (RST)" : "연결 해제 요청 (FIN)");
        if (c) {
            if (d && t->fin) d->next_seq++;
            /* FIN: 이 방향 데이터 끝 -> 길이 모르는 HTTP/1 본문 마무리 */
            if (c->proto == P_HTTP1) h1_close(&c->d[dirn].h1, dirn);
            c->d[dirn].fin = 1;
            if (t->rst || (c->d[0].fin && c->d[1].fin)) {
                printf("  ▷ 연결 #%d 종료\n", c->id);
                conn_free(c);
            }
        }
    }
}

/* ── UDP: 53번(DNS)만 헤더 요약 (DNS 내용 분석은 DNS 담당 모듈) ── */
static void handle_udp(const struct ethhdr *eth, const struct iphdr *ip, const uint8_t *seg, size_t seglen,
                       const char *dir_label, const char *ts)
{
    if (seglen < sizeof(struct udphdr)) return;
    const struct udphdr *u = (const struct udphdr *)seg;
    uint16_t sp = ntohs(u->source), dp = ntohs(u->dest);
    if (sp != 53 && dp != 53) return;
    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN];
    printf("\n──── #%lu %s %s ────\n", pkt_no, ts, dir_label);
    print_eth(eth);
    printf(" IPv4     : %s -> %s  ttl=%u  proto=17 (UDP)\n", ip_str(ip->saddr, a), ip_str(ip->daddr, b), ip->ttl);
    printf(" UDP      : %u -> %u  len=%u  (DNS %s)\n", sp, dp, ntohs(u->len), dp == 53 ? "질의" : "응답");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: sudo %s <interface> [-v] [port ...]\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) verbose = 1;
        else if (nports < MAX_PORTS) ports[nports++] = (uint16_t)atoi(argv[i]);
    }
    if (nports == 0) { ports[0] = 80; ports[1] = 8080; ports[2] = 8000; nports = 3; }

    /* 1) raw socket: 모든 이더넷 프레임 (송신·수신) */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket (root 권한 필요)"); return 1; }

    struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL) };
    sll.sll_ifindex = (int)if_nametoindex(ifname);
    if (!sll.sll_ifindex) { fprintf(stderr, "인터페이스 없음: %s\n", ifname); return 1; }
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) { perror("bind"); return 1; }

    struct timeval tv = { .tv_sec = 1 };            /* Ctrl+C가 바로 먹히게 1초 타임아웃 */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    signal(SIGINT, on_sigint);
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("미니 Wireshark — %s 캡처 시작 (HTTP 포트:", ifname);
    for (int i = 0; i < nports; i++) printf(" %u", ports[i]);
    printf(", DNS 53/udp)  Ctrl+C로 종료\n");

    static uint8_t frame[SNAPLEN];
    while (!stop) {
        struct sockaddr_ll from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(fd, frame, sizeof(frame), 0, (struct sockaddr *)&from, &fl);
        if (n < 0) continue;
        pkt_no++;

        /* 2) Ethernet 헤더 */
        if ((size_t)n < sizeof(struct ethhdr)) continue;
        const struct ethhdr *eth = (const struct ethhdr *)frame;
        if (ntohs(eth->h_proto) != ETH_P_IP) continue;  /* IPv4만 */

        /* 3) IP 헤더 */
        const struct iphdr *ip = (const struct iphdr *)(frame + sizeof(*eth));
        size_t avail = (size_t)n - sizeof(*eth);
        if (avail < sizeof(*ip) || ip->version != 4) continue;
        size_t ihl = ip->ihl * 4u, tot = ntohs(ip->tot_len);
        if (ihl < 20 || tot < ihl || tot > avail) tot = avail;   /* GRO 등으로 길이가 다를 때 */
        if (ihl > tot) continue;

        const char *dir_label = from.sll_pkttype == PACKET_OUTGOING ? "OUT(송신)" : "IN(수신)";
        struct timeval now; gettimeofday(&now, NULL);
        char ts[32]; struct tm tmv; localtime_r(&now.tv_sec, &tmv);
        snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%06ld", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (long)now.tv_usec);

        const uint8_t *seg = (const uint8_t *)ip + ihl;
        size_t seglen = tot - ihl;
        if (ip->protocol == IPPROTO_TCP)      handle_tcp(eth, ip, seg, seglen, dir_label, ts);
        else if (ip->protocol == IPPROTO_UDP) handle_udp(eth, ip, seg, seglen, dir_label, ts);

    }

    printf("\n캡처 종료: 총 %lu 프레임 수신\n", pkt_no);
    for (int i = 0; i < MAX_CONN; i++) if (conns[i].used) conn_free(&conns[i]);
    close(fd);
    return 0;
}
