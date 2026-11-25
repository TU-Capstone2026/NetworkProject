/*
 * main.c - Raw Socket(AF_PACKET) 기반 BitTorrent 패킷 캡처·분석 프로그램
 *
 *   컴퓨터네트워크 설계 3팀 - BitTorrent 담당 (류상진)
 *
 *   처리 흐름
 *     CAPTURE  : socket(AF_PACKET, SOCK_RAW, ETH_P_ALL) 로 송신·수신 프레임을 모두 수신
 *     CLASSIFY : Ethernet → IPv4 → TCP / UDP 헤더를 바이트 단위로 직접 해석
 *     ANALYZE  : 응용 계층 데이터를 bittorrent.c 에 넘겨 BitTorrent 여부 판별·해석
 *     OUTPUT   : 공통 형식(번호, 시각, 송수신 방향, IP/TCP/UDP 헤더) + 응용 계층 정보 출력
 *
 *   빌드 : make
 *   실행 : sudo ./bt_sniffer [-i 인터페이스] [-p 포트] [-a] [-v] [-c 개수]
 */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>       /* ETH_P_ALL, ETH_P_IP */
#include <linux/if_packet.h>    /* struct sockaddr_ll, PACKET_OUTGOING ... */

#include "common.h"
#include "bittorrent.h"

#define BUF_SIZE     70000      /* IPv4 최대 길이(65535) + 링크 계층 헤더 여유 */
#define ETH_HDR_LEN  14
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100

#ifndef ARPHRD_RAWIP
#define ARPHRD_RAWIP 519
#endif

/* ------------------------------------------------------------------ */
/* 옵션 / 통계                                                         */
/* ------------------------------------------------------------------ */
struct options {
    const char *iface;     /* -i : 캡처할 인터페이스 (없으면 전체) */
    int   show_all;        /* -a : BitTorrent 가 아닌 TCP/UDP 패킷도 한 줄로 출력 */
    int   verbose;         /* -v : piece 데이터 이어짐, 재전송, 순수 ACK 까지 출력 */
    int   dedup_lo;        /* -d : lo 에서 같은 패킷이 송신/수신으로 두 번 잡히는 것 중 하나만 */
    long  max_count;       /* -c : BitTorrent 패킷을 이 개수만큼 출력하면 종료 */
    uint16_t ports[8];     /* -p : BitTorrent 클라이언트 포트 (연결 설정 표시용) */
    int   nports;
};

static struct {
    unsigned long total, out, in, other, lo_dup;
    unsigned long ipv4, tcp, udp;
    unsigned long bt_printed;
} g_stat;

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* 빅엔디언(네트워크 바이트 순서) 읽기 */
static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* ------------------------------------------------------------------ */
/* 공통 출력 함수 (common.h)                                           */
/* ------------------------------------------------------------------ */
const char *dir_str(enum pkt_dir d)
{
    switch (d) {
    case DIR_OUT: return "송신";
    case DIR_IN:  return "수신";
    default:      return "기타";
    }
}

const char *time_str(const struct timeval *tv, char *buf, size_t bufsz)
{
    struct tm tm;
    time_t sec = tv->tv_sec;
    char hms[16];
    localtime_r(&sec, &tm);
    strftime(hms, sizeof hms, "%H:%M:%S", &tm);
    snprintf(buf, bufsz, "%s.%03ld", hms, (long)(tv->tv_usec / 1000));
    return buf;
}

const char *tcp_flags_str(uint8_t f, char *buf, size_t bufsz)
{
    static const struct { uint8_t bit; const char *name; } tbl[] = {
        { TF_SYN, "SYN" }, { TF_FIN, "FIN" }, { TF_RST, "RST" },
        { TF_PSH, "PSH" }, { TF_ACK, "ACK" }, { TF_URG, "URG" },
    };
    size_t used = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < sizeof tbl / sizeof tbl[0]; i++) {
        if (f & tbl[i].bit) {
            int w = snprintf(buf + used, bufsz - used, "%s%s", used ? "," : "", tbl[i].name);
            if (w < 0 || (size_t)w >= bufsz - used) break;
            used += (size_t)w;
        }
    }
    return buf;
}

void print_pkt_header(const struct pkt_info *pi, const char *app_title)
{
    char tb[32], fb[40];

    printf("------------------------------------------------------------------------\n");
    printf("#%lu [%s] [%s] %s\n", pi->pkt_no, time_str(&pi->ts, tb, sizeof tb),
           dir_str(pi->dir), app_title);

    /* IP 헤더 */
    printf(" [IP ] %s -> %s  TTL=%u  ID=0x%04x  TotalLen=%u  Proto=%s(%u)\n",
           pi->src_ip, pi->dst_ip, pi->ttl, pi->ip_id, pi->ip_total_len,
           pi->ip_proto == IPPROTO_TCP ? "TCP" : "UDP", pi->ip_proto);

    /* TCP / UDP 헤더 */
    if (pi->ip_proto == IPPROTO_TCP) {
        printf(" [TCP] %u -> %u  Seq=%u  Ack=%u  Flags=[%s]  Win=%u  HdrLen=%u  Len=%zu\n",
               pi->src_port, pi->dst_port, pi->seq, pi->ack,
               tcp_flags_str(pi->tcp_flags, fb, sizeof fb), pi->window,
               pi->tcp_hdr_len, pi->payload_len);
    } else {
        printf(" [UDP] %u -> %u  Length=%u  (데이터 %zu bytes)\n",
               pi->src_port, pi->dst_port, pi->udp_len, pi->payload_len);
    }
}

/* -a 옵션: BitTorrent 가 아닌 패킷은 한 줄 요약 */
static void print_brief(const struct pkt_info *pi)
{
    char tb[32], fb[40];
    if (pi->ip_proto == IPPROTO_TCP)
        printf("#%lu [%s] [%s] TCP %s:%u -> %s:%u  Flags=[%s] Len=%zu\n",
               pi->pkt_no, time_str(&pi->ts, tb, sizeof tb), dir_str(pi->dir),
               pi->src_ip, pi->src_port, pi->dst_ip, pi->dst_port,
               tcp_flags_str(pi->tcp_flags, fb, sizeof fb), pi->payload_len);
    else
        printf("#%lu [%s] [%s] UDP %s:%u -> %s:%u  Len=%zu\n",
               pi->pkt_no, time_str(&pi->ts, tb, sizeof tb), dir_str(pi->dir),
               pi->src_ip, pi->src_port, pi->dst_ip, pi->dst_port, pi->payload_len);
}

/* ------------------------------------------------------------------ */
/* 계층별 헤더 해석                                                     */
/* ------------------------------------------------------------------ */

/* sll_pkttype → 송신/수신 */
static enum pkt_dir pkttype_to_dir(unsigned char t)
{
    switch (t) {
    case PACKET_OUTGOING:  return DIR_OUT;
    case PACKET_HOST:
    case PACKET_BROADCAST:
    case PACKET_MULTICAST: return DIR_IN;
    default:               return DIR_OTHER;
    }
}

/* TCP / UDP 헤더 해석 후 BitTorrent 모듈 호출 */
static void handle_l4(struct pkt_info *pi, const uint8_t *l4, size_t l4len,
                      const struct options *opt)
{
    int printed;

    if (pi->ip_proto == IPPROTO_TCP) {
        /*
         *  0      2      4          8          12   13    14     16
         *  +------+------+----------+----------+----+-----+------+------+
         *  |SPort |DPort |   Seq    |   Ack    |Off |Flags|Window| ...  |
         */
        if (l4len < 20) return;
        uint8_t doff = (uint8_t)((l4[12] >> 4) * 4);
        if (doff < 20 || doff > l4len) return;
        pi->src_port    = be16(l4);
        pi->dst_port    = be16(l4 + 2);
        pi->seq         = be32(l4 + 4);
        pi->ack         = be32(l4 + 8);
        pi->tcp_hdr_len = doff;
        pi->tcp_flags   = l4[13];
        pi->window      = be16(l4 + 14);
        pi->payload     = l4 + doff;
        pi->payload_len = l4len - doff;
        g_stat.tcp++;
        printed = bt_analyze_tcp(pi);
    } else if (pi->ip_proto == IPPROTO_UDP) {
        /*  0      2      4      6      8
         *  +------+------+------+------+
         *  |SPort |DPort |Length|Chksum|
         */
        if (l4len < 8) return;
        uint16_t ulen = be16(l4 + 4);
        if (ulen < 8) return;
        size_t usable = ulen < l4len ? ulen : l4len;
        pi->src_port    = be16(l4);
        pi->dst_port    = be16(l4 + 2);
        pi->udp_len     = ulen;
        pi->payload     = l4 + 8;
        pi->payload_len = usable - 8;
        g_stat.udp++;
        printed = bt_analyze_udp(pi);
    } else {
        return;   /* ICMP 등은 이 프로그램의 분석 대상이 아님 */
    }

    if (printed)
        g_stat.bt_printed++;
    else if (opt->show_all)
        print_brief(pi);
}

/* IPv4 헤더 해석 */
static void handle_ipv4(const uint8_t *p, size_t len, enum pkt_dir dir,
                        const struct timeval *ts, const struct options *opt)
{
    /*
     *  0        1      2         4      6          8     9      10       12     16     20
     *  +--------+------+---------+------+----------+-----+------+--------+------+------+
     *  |Ver|IHL | TOS  |TotalLen |  ID  |Flags/Frag| TTL |Proto |Checksum| SrcIP| DstIP|
     */
    if (len < 20) return;
    uint8_t ver = p[0] >> 4;
    uint8_t ihl = (uint8_t)((p[0] & 0x0f) * 4);
    if (ver != 4 || ihl < 20 || ihl > len) return;

    uint16_t tot = be16(p + 2);
    if (tot < ihl) return;
    /* Ethernet 최소 길이 패딩은 제외하고, 캡처가 잘린 경우엔 받은 만큼만 사용 */
    size_t ip_len = tot <= len ? tot : len;

    /* 조각화된 패킷 중 첫 조각이 아니면 TCP/UDP 헤더가 없음 → 건너뜀 */
    if (be16(p + 6) & 0x1fff) return;

    struct pkt_info pi;
    memset(&pi, 0, sizeof pi);
    pi.pkt_no       = g_stat.total;
    pi.ts           = *ts;
    pi.dir          = dir;
    pi.ip_hdr_len   = ihl;
    pi.ip_total_len = tot;
    pi.ip_id        = be16(p + 4);
    pi.ttl          = p[8];
    pi.ip_proto     = p[9];
    memcpy(&pi.src_addr, p + 12, 4);
    memcpy(&pi.dst_addr, p + 16, 4);
    inet_ntop(AF_INET, &pi.src_addr, pi.src_ip, sizeof pi.src_ip);
    inet_ntop(AF_INET, &pi.dst_addr, pi.dst_ip, sizeof pi.dst_ip);

    g_stat.ipv4++;
    handle_l4(&pi, p + ihl, ip_len - ihl, opt);
}

/* 링크 계층(Ethernet) 해석 */
static void handle_frame(const uint8_t *buf, size_t n, const struct sockaddr_ll *sll,
                         const struct timeval *ts, const struct options *opt)
{
    enum pkt_dir dir = pkttype_to_dir(sll->sll_pkttype);
    size_t off;

    /* 루프백은 커널이 같은 패킷을 송신(OUTGOING) 사본과 수신(HOST) 사본으로 두 번 넘겨준다.
     * -d 옵션이면 수신 사본은 건너뛴다 (Wireshark 의 lo 캡처와 개수가 같아짐). */
    if (opt->dedup_lo && sll->sll_hatype == ARPHRD_LOOPBACK && sll->sll_pkttype == PACKET_HOST) {
        g_stat.lo_dup++;
        return;
    }

    g_stat.total++;
    if (dir == DIR_OUT) g_stat.out++;
    else if (dir == DIR_IN) g_stat.in++;
    else g_stat.other++;

    switch (sll->sll_hatype) {
    case ARPHRD_ETHER:
    case ARPHRD_LOOPBACK: {
        /* Ethernet 헤더: 목적지 MAC(6) + 출발지 MAC(6) + EtherType(2) */
        if (n < ETH_HDR_LEN) return;
        uint16_t type = be16(buf + 12);
        off = ETH_HDR_LEN;
        if (type == ETHERTYPE_VLAN) {          /* 802.1Q VLAN 태그 1개까지 처리 */
            if (n < ETH_HDR_LEN + 4) return;
            type = be16(buf + 16);
            off += 4;
        }
        if (type != ETHERTYPE_IPV4) return;    /* IPv6, ARP 등은 대상 아님 */
        break;
    }
    case ARPHRD_NONE:       /* tun (VPN) 처럼 링크 계층 헤더가 없는 인터페이스 */
    case ARPHRD_PPP:
    case ARPHRD_RAWIP:
        if (n < 1 || (buf[0] >> 4) != 4) return;
        off = 0;
        break;
    default:
        return;
    }
    handle_ipv4(buf + off, n - off, dir, ts, opt);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    fprintf(stderr,
        "사용법: sudo %s [-i 인터페이스] [-p 포트] [-a] [-v] [-d] [-c 개수]\n"
        "  -i IFACE  캡처할 인터페이스 (예: lo, eth0, enp0s3, wlan0). 생략 시 전체\n"
        "  -p PORT   BitTorrent 클라이언트 리슨 포트 (최대 8개, 6881~6889 는 기본 포함)\n"
        "  -a        BitTorrent 가 아닌 TCP/UDP 패킷도 한 줄 요약으로 출력\n"
        "  -v        상세 출력 (piece 데이터 이어짐, 재전송, 순수 ACK 포함)\n"
        "  -d        lo 에서 같은 패킷이 송신/수신으로 두 번 잡히는 것을 한 번만 출력\n"
        "  -c N      BitTorrent 패킷 N개를 출력하면 종료\n"
        "  Ctrl+C    캡처 종료 후 통계 출력\n", prog);
}

static int parse_args(int argc, char **argv, struct options *opt)
{
    int c;
    memset(opt, 0, sizeof *opt);
    while ((c = getopt(argc, argv, "i:p:avdc:h")) != -1) {
        switch (c) {
        case 'i': opt->iface = optarg; break;
        case 'p': {
            long v = strtol(optarg, NULL, 10);
            if (v <= 0 || v > 65535) { fprintf(stderr, "잘못된 포트: %s\n", optarg); return -1; }
            if (opt->nports < 8) opt->ports[opt->nports++] = (uint16_t)v;
            break;
        }
        case 'a': opt->show_all = 1; break;
        case 'v': opt->verbose = 1; break;
        case 'd': opt->dedup_lo = 1; break;
        case 'c': opt->max_count = strtol(optarg, NULL, 10); break;
        default:  return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct options opt;
    if (parse_args(argc, argv, &opt) < 0) { usage(argv[0]); return 1; }

    /* 파이프(tee)로 저장할 때도 바로바로 보이도록 줄 단위 버퍼링 */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Ctrl+C 로 종료할 때 recvfrom 이 바로 깨어나도록 SA_RESTART 없이 등록 */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* 1) Raw Socket 생성: 링크 계층부터 모든 프로토콜(ETH_P_ALL)의 송신·수신 프레임 수신 */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket(AF_PACKET)");
        fprintf(stderr, "Raw Socket 은 root 권한이 필요합니다. sudo 로 실행하세요.\n");
        return 1;
    }

    /* 2) 인터페이스 지정 시 해당 인터페이스에만 bind */
    if (opt.iface) {
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof sll);
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex  = (int)if_nametoindex(opt.iface);
        if (sll.sll_ifindex == 0) {
            fprintf(stderr, "인터페이스 '%s' 를 찾을 수 없습니다. (ip a 로 이름 확인)\n", opt.iface);
            close(sock);
            return 1;
        }
        if (bind(sock, (struct sockaddr *)&sll, sizeof sll) < 0) {
            perror("bind");
            close(sock);
            return 1;
        }
    }

    bt_init(opt.verbose, opt.ports, opt.nports);

    printf("BitTorrent 패킷 분석기 - 인터페이스: %s  (Ctrl+C 로 종료)\n",
           opt.iface ? opt.iface : "전체");

    uint8_t *buf = malloc(BUF_SIZE);
    if (!buf) { perror("malloc"); close(sock); return 1; }

    /* 3) 캡처 루프 */
    while (!g_stop) {
        struct sockaddr_ll from;
        socklen_t fromlen = sizeof from;
        ssize_t n = recvfrom(sock, buf, BUF_SIZE, 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }
        struct timeval ts;
        gettimeofday(&ts, NULL);

        handle_frame(buf, (size_t)n, &from, &ts, &opt);

        if (opt.max_count > 0 && (long)g_stat.bt_printed >= opt.max_count)
            break;
    }

    /* 4) 통계 출력 */
    printf("\n=================== 캡처 통계 ===================\n");
    printf(" 전체 프레임        : %lu (송신 %lu / 수신 %lu / 기타 %lu)\n",
           g_stat.total, g_stat.out, g_stat.in, g_stat.other);
    if (opt.dedup_lo)
        printf(" lo 중복 사본 제외   : %lu\n", g_stat.lo_dup);
    printf(" IPv4 / TCP / UDP   : %lu / %lu / %lu\n", g_stat.ipv4, g_stat.tcp, g_stat.udp);
    printf(" BitTorrent 출력    : %lu 패킷\n", g_stat.bt_printed);
    bt_print_stats();

    free(buf);
    close(sock);
    return 0;
}
