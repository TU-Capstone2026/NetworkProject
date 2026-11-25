/*
 * common.h - 캡처한 패킷의 공통 정보 구조체와 출력 함수 선언
 *
 * main.c 가 Ethernet / IPv4 / TCP / UDP 헤더를 해석해서 struct pkt_info 에 채우고,
 * 응용 계층 분석 모듈(bittorrent.c)은 이 구조체만 보고 분석한다.
 * 나중에 팀 공용 레포에 합칠 때도 이 구조체 형식만 맞추면 된다.
 */
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>
#include <netinet/in.h>

/* 송수신 방향 (AF_PACKET 의 sll_pkttype 으로 판단) */
enum pkt_dir {
    DIR_OUT   = 0,   /* PACKET_OUTGOING : 이 컴퓨터가 보낸 패킷 */
    DIR_IN    = 1,   /* PACKET_HOST / BROADCAST / MULTICAST : 이 컴퓨터가 받은 패킷 */
    DIR_OTHER = 2    /* PACKET_OTHERHOST : 다른 호스트로 가는 패킷(무차별 모드일 때) */
};

/* TCP 플래그 비트 (TCP 헤더 13번째 바이트) */
#define TF_FIN 0x01
#define TF_SYN 0x02
#define TF_RST 0x04
#define TF_PSH 0x08
#define TF_ACK 0x10
#define TF_URG 0x20

struct pkt_info {
    unsigned long  pkt_no;        /* 캡처 순번 */
    struct timeval ts;            /* 캡처 시각 */
    enum pkt_dir   dir;           /* 송신 / 수신 */

    /* ---- IPv4 헤더 ---- */
    uint32_t src_addr, dst_addr;  /* 네트워크 바이트 순서 그대로 */
    char     src_ip[INET_ADDRSTRLEN];
    char     dst_ip[INET_ADDRSTRLEN];
    uint8_t  ip_hdr_len;          /* IHL * 4 */
    uint16_t ip_total_len;        /* Total Length */
    uint16_t ip_id;               /* Identification */
    uint8_t  ttl;                 /* Time To Live */
    uint8_t  ip_proto;            /* 6 = TCP, 17 = UDP */

    /* ---- TCP / UDP 공통 ---- */
    uint16_t src_port, dst_port;

    /* ---- TCP 헤더 ---- */
    uint32_t seq, ack;            /* Sequence Number, Acknowledgement Number (raw 값) */
    uint8_t  tcp_hdr_len;         /* Data Offset * 4 */
    uint8_t  tcp_flags;           /* TF_* 비트 */
    uint16_t window;

    /* ---- UDP 헤더 ---- */
    uint16_t udp_len;             /* UDP Length (헤더 8바이트 포함) */

    /* ---- 응용 계층 데이터 ---- */
    const uint8_t *payload;
    size_t         payload_len;
};

/* 공통 출력: 패킷 번호, 시각, 방향, IP 헤더, TCP/UDP 헤더 */
void print_pkt_header(const struct pkt_info *pi, const char *app_title);

/* TCP 플래그를 "SYN,ACK" 형태 문자열로 */
const char *tcp_flags_str(uint8_t flags, char *buf, size_t bufsz);

/* 방향 문자열 ("송신" / "수신" / "기타") */
const char *dir_str(enum pkt_dir d);

/* 시각을 "HH:MM:SS.mmm" 형태로 */
const char *time_str(const struct timeval *tv, char *buf, size_t bufsz);

#endif /* COMMON_H */
