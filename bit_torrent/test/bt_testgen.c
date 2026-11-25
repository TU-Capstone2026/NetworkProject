/*
 * bt_testgen.c - BitTorrent 분석기 검증용 테스트 트래픽 생성기
 *
 *   실제 토렌트 없이, 값이 정해진 BitTorrent 패킷을 루프백(127.0.0.1)으로 주고받는다.
 *   같은 시간에 bt_sniffer 와 Wireshark 로 lo 를 캡처해서 결과를 대조하는 용도.
 *
 *   한 프로세스가 양쪽 소켓(내 클라이언트 / 상대 피어·트래커)을 모두 열고
 *   정해진 순서대로 번갈아 보내고 받는다. 스레드가 없어도 순서가 고정이므로
 *   매번 같은 패킷 흐름이 나온다. 일반 소켓만 쓰므로 root 권한은 필요 없다.
 *
 *   빌드 : make                  (→ test/bt_testgen)
 *   사용법
 *     터미널 1:  sudo ./bt_sniffer -i lo -d
 *     터미널 2:  ./test/bt_testgen
 *
 *   발생시키는 트래픽
 *     1) TCP  127.0.0.1:6881  Peer Wire  - 3-way handshake, 핸드셰이크, bitfield, 확장 핸드셰이크,
 *                                          interested/unchoke/request/piece(여러 세그먼트),
 *                                          헤더가 두 세그먼트로 나뉜 have, port, cancel,
 *                                          keep-alive, choke, 연결 해제(FIN)
 *     2) TCP  127.0.0.1:6969  HTTP 트래커 - announce 요청 / bencode 응답
 *     3) UDP  127.0.0.1:6969  UDP 트래커  - connect, announce, scrape, error
 *     4) UDP  127.0.0.1:6881 <-> 6882  DHT - ping, find_node, get_peers, announce_peer, error
 *     5) TCP  127.0.0.1:6881  암호화(MSE) 흉내 - 평문 핸드셰이크 없이 임의 바이트만 오가는 연결
 */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>        /* TCP_NODELAY */
#include <arpa/inet.h>

#define HOST          "127.0.0.1"
#define PEER_PORT     6881      /* TCP Peer Wire */
#define TRACKER_PORT  6969      /* HTTP 트래커(TCP) / UDP 트래커(UDP) */
#define DHT_PORT_A    6881      /* DHT 노드 A (UDP) */
#define DHT_PORT_B    6882      /* DHT 노드 B (UDP) */

#define BLOCK         16384     /* piece 블록 크기 */
#define GAP_MS        150       /* 패킷 사이 간격 - 세그먼트가 합쳐지지 않도록 */
#define UDPT_MAGIC    0x41727101980ULL

/* SHA-1 값은 미리 계산한 상수 (확인: printf '%s' '문자열' | sha1sum) */
static const char INFO_HASH_HEX[] = "5a27bfa7070c7f62de1c67dead9ddb5b97b6acd1"; /* "computer network design team3 test torrent" */
static const char NODE_A_HEX[]    = "a9702972aa8239c001790d539f109779ab1f27ca"; /* "dht node A" */
static const char NODE_B_HEX[]    = "dd75c3608f550a7a028a05621b6981032af06638"; /* "dht node B" */
static const char NODE_N1_HEX[]   = "40b3eab63f3f1d4fa48e09559401c5ed4efceaa6"; /* "n1" (find_node 응답용) */
static const char NODE_N2_HEX[]   = "40243476fcaaf8dca4d9eda7fde4232c5c18f75d"; /* "n2" */

static uint8_t INFO_HASH[20], NODE_A[20], NODE_B[20], NODE_N1[20], NODE_N2[20];

static const char CLIENT_PEER_ID[] = "-qB4650-TEAM3CLIENT1";   /* 20 bytes, qBittorrent 4.6.5 형식 */
static const char SERVER_PEER_ID[] = "-TR4050-TEAM3SERVER1";   /* 20 bytes, Transmission 4.0.5 형식 */

/* ====================================================================== */
/* 공통 도우미                                                              */
/* ====================================================================== */
static void die(const char *what)
{
    perror(what);
    exit(1);
}

static void fail(const char *msg)
{
    fprintf(stderr, "오류: %s\n", msg);
    exit(1);
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void gap(void) { sleep_ms(GAP_MS); }

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) fail("hex 상수 형식 오류");
        out[i] = (uint8_t)v;
    }
}

static void print_hex(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

/* 압축(compact) 형식 6 bytes = IPv4(4) + Port(2), 모두 네트워크 바이트 순서 */
static void compact6(uint8_t out[6], const char *ip, uint16_t port)
{
    if (inet_pton(AF_INET, ip, out) != 1) fail("IP 주소 형식 오류");
    out[4] = (uint8_t)(port >> 8);
    out[5] = (uint8_t)port;
}

/* ====================================================================== */
/* 보낼 데이터를 차례로 쌓는 버퍼 (빅엔디언 = 네트워크 바이트 순서)              */
/* ====================================================================== */
struct buf {
    uint8_t d[17000];           /* 가장 큰 것은 piece 메시지 16397 bytes */
    size_t  n;
};

static void put(struct buf *b, const void *p, size_t len)
{
    if (b->n + len > sizeof b->d) fail("버퍼 크기 초과");
    memcpy(b->d + b->n, p, len);
    b->n += len;
}

static void put_u8(struct buf *b, uint8_t v) { put(b, &v, 1); }

static void put_u16(struct buf *b, uint16_t v)
{
    uint8_t t[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    put(b, t, 2);
}

static void put_u32(struct buf *b, uint32_t v)
{
    uint8_t t[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    put(b, t, 4);
}

static void put_u64(struct buf *b, uint64_t v)
{
    put_u32(b, (uint32_t)(v >> 32));
    put_u32(b, (uint32_t)v);
}

static void put_text(struct buf *b, const char *s) { put(b, s, strlen(s)); }

/* ---------------------------------------------------------------------- */
/* bencode (BEP 3)                                                         */
/*   문자열 <길이>:<내용>, 정수 i<숫자>e, 리스트 l...e, 딕셔너리 d...e        */
/*   딕셔너리의 키는 반드시 사전순으로 써야 한다.                              */
/* ---------------------------------------------------------------------- */
static void be_bytes(struct buf *b, const void *p, size_t len)
{
    char h[24];
    snprintf(h, sizeof h, "%zu:", len);
    put_text(b, h);
    put(b, p, len);
}

static void be_str(struct buf *b, const char *s) { be_bytes(b, s, strlen(s)); }

static void be_int(struct buf *b, long long v)
{
    char t[32];
    snprintf(t, sizeof t, "i%llde", v);
    put_text(b, t);
}

static void be_dict(struct buf *b) { put_text(b, "d"); }
static void be_list(struct buf *b) { put_text(b, "l"); }
static void be_end(struct buf *b)  { put_text(b, "e"); }

/* ====================================================================== */
/* 소켓 도우미                                                              */
/* ====================================================================== */
static struct sockaddr_in addr_of(uint16_t port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    inet_pton(AF_INET, HOST, &a.sin_addr);
    return a;
}

/* 상대가 응답하지 않을 때 영원히 멈추지 않도록 수신 대기 시간 제한 */
static void set_timeout(int fd)
{
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

static int tcp_listen(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a = addr_of(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
    if (listen(fd, 1) < 0) die("listen");
    return fd;
}

/* connect 하는 순간 커널이 3-way handshake 를 끝낸다 (accept 전이어도 backlog 에 들어감) */
static int tcp_connect(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");
    struct sockaddr_in a = addr_of(port);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) die("connect");
    set_timeout(fd);
    return fd;
}

static int tcp_accept(int lfd)
{
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0) die("accept");
    set_timeout(fd);
    return fd;
}

/* Nagle 알고리즘 끄기 - 작은 메시지가 한 세그먼트로 합쳐지지 않게 */
static void nodelay(int fd)
{
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
}

static int udp_socket(int bind_port)     /* bind_port 가 0 이면 bind 하지 않음 */
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) die("socket");
    if (bind_port) {
        struct sockaddr_in a = addr_of((uint16_t)bind_port);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
    }
    set_timeout(fd);
    return fd;
}

static void send_all(int fd, const void *p, size_t n)
{
    const uint8_t *q = p;
    while (n > 0) {
        ssize_t w = send(fd, q, n, 0);
        if (w < 0) die("send");
        q += w;
        n -= (size_t)w;
    }
}

static void send_buf(int fd, const struct buf *b) { send_all(fd, b->d, b->n); }

static void recv_exact(int fd, void *p, size_t n)
{
    uint8_t *q = p;
    while (n > 0) {
        ssize_t r = recv(fd, q, n, 0);
        if (r < 0) die("recv");
        if (r == 0) fail("연결 끊김");
        q += r;
        n -= (size_t)r;
    }
}

/* Peer Wire 메시지 하나 받기: 길이 4 bytes 를 읽고 그만큼 더 읽는다. 내용 길이를 반환 */
static uint32_t recv_msg(int fd, uint8_t *out, size_t outmax)
{
    uint8_t h[4];
    recv_exact(fd, h, 4);
    uint32_t len = rd32(h);
    if (len > outmax) fail("받은 메시지가 너무 김");
    recv_exact(fd, out, len);
    return len;
}

/* 상대가 연결을 닫을 때(FIN 수신 → recv 가 0 반환)까지 기다림 */
static void wait_close(int fd)
{
    uint8_t c;
    while (recv(fd, &c, 1, 0) > 0)
        ;
}

/* ====================================================================== */
/* 1) TCP Peer Wire                                                         */
/* ====================================================================== */

/* [19]["BitTorrent protocol"][reserved 8][info_hash 20][peer_id 20] = 68 bytes */
static void put_handshake(struct buf *b, const char *peer_id)
{
    static const uint8_t reserved[8] = { 0, 0, 0, 0, 0, 0x10, 0, 0x05 };  /* Extension(BEP10) + Fast + DHT */
    put_u8(b, 19);
    put_text(b, "BitTorrent protocol");
    put(b, reserved, 8);
    put(b, INFO_HASH, 20);
    put(b, peer_id, 20);
}

/* 메시지 앞부분 [길이 4B][ID 1B]. 길이 = ID 1 byte + 내용 */
static void put_msg_hdr(struct buf *b, uint8_t id, uint32_t payload_len)
{
    put_u32(b, 1 + payload_len);
    put_u8(b, id);
}

/* index / begin / length 를 갖는 메시지 (request, cancel) */
static void put_block_msg(struct buf *b, uint8_t id, uint32_t index, uint32_t begin, uint32_t length)
{
    put_msg_hdr(b, id, 12);
    put_u32(b, index);
    put_u32(b, begin);
    put_u32(b, length);
}

/* 확장 핸드셰이크(BEP 10) 내용. 키 사전순: m, metadata_size, p, reqq, v, yourip */
static void build_ext_handshake(struct buf *b)
{
    uint8_t ip[4];
    inet_pton(AF_INET, HOST, ip);

    be_dict(b);
    be_str(b, "m");
        be_dict(b);
        be_str(b, "ut_metadata"); be_int(b, 2);
        be_str(b, "ut_pex");      be_int(b, 1);
        be_end(b);
    be_str(b, "metadata_size"); be_int(b, 31337);
    be_str(b, "p");             be_int(b, PEER_PORT);
    be_str(b, "reqq");          be_int(b, 500);
    be_str(b, "v");             be_str(b, "Transmission 4.0.5");
    be_str(b, "yourip");        be_bytes(b, ip, 4);
    be_end(b);
}

static void test_peer_wire(void)
{
    struct buf m, ext;
    uint8_t rx[BLOCK + 64];

    printf("[1/5] TCP Peer Wire (127.0.0.1:%d)\n", PEER_PORT);

    int lfd = tcp_listen(PEER_PORT);
    int cli = tcp_connect(PEER_PORT);     /* 내 클라이언트 (qBittorrent 라고 가정) */
    int srv = tcp_accept(lfd);            /* 상대 피어 (Transmission 이라고 가정) */
    nodelay(cli);
    nodelay(srv);

    /* 클라이언트 → 핸드셰이크 */
    gap();
    m.n = 0;
    put_handshake(&m, CLIENT_PEER_ID);
    send_buf(cli, &m);
    recv_exact(srv, rx, 68);

    /* 피어 → 핸드셰이크 + bitfield + 확장 핸드셰이크를 한 세그먼트에 (메시지 여러 개가 붙어 오는 경우) */
    ext.n = 0;
    build_ext_handshake(&ext);
    m.n = 0;
    put_handshake(&m, SERVER_PEER_ID);
    put_msg_hdr(&m, 5, 2);                         /* bitfield: 조각 10개(0~9번) 모두 보유 */
    put_u8(&m, 0xff);                              /*   11111111 */
    put_u8(&m, 0xc0);                              /*   11000000 */
    put_msg_hdr(&m, 20, 1 + (uint32_t)ext.n);      /* extended, 확장 ID 0 = 확장 핸드셰이크 */
    put_u8(&m, 0);
    put(&m, ext.d, ext.n);
    send_buf(srv, &m);

    recv_exact(cli, rx, 68);
    recv_msg(cli, rx, sizeof rx);                  /* bitfield */
    recv_msg(cli, rx, sizeof rx);                  /* extended handshake */

    /* 클라이언트 → interested, 피어 → unchoke */
    gap();
    m.n = 0; put_msg_hdr(&m, 2, 0); send_buf(cli, &m);
    recv_msg(srv, rx, sizeof rx);
    gap();
    m.n = 0; put_msg_hdr(&m, 1, 0); send_buf(srv, &m);
    recv_msg(cli, rx, sizeof rx);

    /* 클라이언트 → request(index 0, begin 0, 16KB) */
    gap();
    m.n = 0; put_block_msg(&m, 6, 0, 0, BLOCK); send_buf(cli, &m);

    /* 피어 → piece. 요청받은 index/begin/length 그대로 응답 */
    recv_msg(srv, rx, sizeof rx);
    uint32_t index = rd32(rx + 1), begin = rd32(rx + 5), length = rd32(rx + 9);
    if (length > BLOCK) fail("요청 블록이 너무 큼");
    m.n = 0;
    put_msg_hdr(&m, 7, 8 + length);
    put_u32(&m, index);
    put_u32(&m, begin);
    for (uint32_t i = 0; i < length; i++) put_u8(&m, (uint8_t)((i * 7) & 0xff));

    /* piece 메시지(16397 bytes)를 5개 세그먼트로 나눠 전송 → 경계 추적 확인 */
    static const size_t cuts[] = { 0, 1013, 5000, 9000, 13000 };
    for (size_t k = 0; k < sizeof cuts / sizeof cuts[0]; k++) {
        size_t a = cuts[k];
        size_t e = k + 1 < sizeof cuts / sizeof cuts[0] ? cuts[k + 1] : m.n;
        gap();
        send_all(srv, m.d + a, e - a);
    }
    recv_msg(cli, rx, sizeof rx);                  /* piece */

    /* 클라이언트 → have(index 0). 헤더가 두 세그먼트로 나뉜 경우 */
    m.n = 0; put_msg_hdr(&m, 4, 4); put_u32(&m, 0);
    gap(); send_all(cli, m.d, 3);
    gap(); send_all(cli, m.d + 3, m.n - 3);

    /* 클라이언트 → port (DHT 포트 알림) */
    gap();
    m.n = 0; put_msg_hdr(&m, 9, 2); put_u16(&m, DHT_PORT_A); send_buf(cli, &m);

    /* 클라이언트 → request + cancel 을 한 세그먼트에 */
    gap();
    m.n = 0;
    put_block_msg(&m, 6, 1, 0, BLOCK);
    put_block_msg(&m, 8, 1, 0, BLOCK);
    send_buf(cli, &m);

    recv_msg(srv, rx, sizeof rx);                  /* have */
    recv_msg(srv, rx, sizeof rx);                  /* port */
    recv_msg(srv, rx, sizeof rx);                  /* request */
    recv_msg(srv, rx, sizeof rx);                  /* cancel */

    /* 피어 → keep-alive (길이 0) */
    gap();
    m.n = 0; put_u32(&m, 0); send_buf(srv, &m);
    recv_msg(cli, rx, sizeof rx);

    /* 클라이언트 → not interested, 피어 → choke */
    gap();
    m.n = 0; put_msg_hdr(&m, 3, 0); send_buf(cli, &m);
    recv_msg(srv, rx, sizeof rx);
    gap();
    m.n = 0; put_msg_hdr(&m, 0, 0); send_buf(srv, &m);
    recv_msg(cli, rx, sizeof rx);

    /* 연결 해제: 클라이언트 FIN → 피어 FIN */
    gap();
    shutdown(cli, SHUT_WR);
    wait_close(srv);
    gap();
    close(srv);
    close(lfd);
    wait_close(cli);
    close(cli);
}

/* ====================================================================== */
/* 2) HTTP 트래커                                                            */
/* ====================================================================== */

/* URL 인코딩: 영문·숫자와 "-._~" 는 그대로, 나머지는 %XX (RFC 3986) */
static void url_encode(char *out, size_t outsz, const uint8_t *p, size_t n)
{
    static const char hx[] = "0123456789ABCDEF";
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = p[i];
        int plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '-' || c == '.' || c == '_' || c == '~';
        if (o + 4 > outsz) fail("URL 버퍼 크기 초과");
        if (plain) {
            out[o++] = (char)c;
        } else {
            out[o++] = '%';
            out[o++] = hx[c >> 4];
            out[o++] = hx[c & 0x0f];
        }
    }
    out[o] = '\0';
}

static void test_http_tracker(void)
{
    char ih[80], pid[80], req[512], hdr[256], rx[4096];
    struct buf body, resp;
    uint8_t c1[6], c2[6];

    printf("[2/5] HTTP 트래커 (127.0.0.1:%d/tcp)\n", TRACKER_PORT);

    int lfd = tcp_listen(TRACKER_PORT);
    int cli = tcp_connect(TRACKER_PORT);
    int srv = tcp_accept(lfd);

    /* 클라이언트 → GET /announce?... */
    url_encode(ih, sizeof ih, INFO_HASH, 20);
    url_encode(pid, sizeof pid, (const uint8_t *)CLIENT_PEER_ID, 20);
    snprintf(req, sizeof req,
             "GET /announce?info_hash=%s&peer_id=%s"
             "&port=6881&uploaded=0&downloaded=0&left=163840&event=started&compact=1&numwant=50 HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "User-Agent: qBittorrent/4.6.5\r\n"
             "Connection: close\r\n\r\n",
             ih, pid, HOST, TRACKER_PORT);
    gap();
    send_all(cli, req, strlen(req));

    /* 트래커: 요청 헤더 끝(빈 줄)까지 받기 */
    size_t got = 0;
    rx[0] = '\0';
    while (!strstr(rx, "\r\n\r\n")) {
        if (got + 1 >= sizeof rx) fail("HTTP 요청이 너무 김");
        ssize_t r = recv(srv, rx + got, sizeof rx - 1 - got, 0);
        if (r <= 0) fail("HTTP 요청 수신 실패");
        got += (size_t)r;
        rx[got] = '\0';
    }

    /* 트래커 → 응답 본문(bencode). 키 사전순: complete, incomplete, interval, min interval, peers */
    compact6(c1, "127.0.0.1", 6881);
    compact6(c2, "10.0.0.2", 51413);
    uint8_t peers[12];
    memcpy(peers, c1, 6);
    memcpy(peers + 6, c2, 6);

    body.n = 0;
    be_dict(&body);
    be_str(&body, "complete");     be_int(&body, 5);
    be_str(&body, "incomplete");   be_int(&body, 3);
    be_str(&body, "interval");     be_int(&body, 1800);
    be_str(&body, "min interval"); be_int(&body, 900);
    be_str(&body, "peers");        be_bytes(&body, peers, sizeof peers);
    be_end(&body);

    snprintf(hdr, sizeof hdr,
             "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n"
             "Connection: close\r\n\r\n", body.n);
    resp.n = 0;                                    /* 헤더와 본문을 한 번에 전송 */
    put_text(&resp, hdr);
    put(&resp, body.d, body.n);
    gap();
    send_buf(srv, &resp);
    close(srv);
    close(lfd);

    /* 클라이언트: 트래커가 연결을 닫을 때까지 응답 수신 */
    while (recv(cli, rx, sizeof rx, 0) > 0)
        ;
    close(cli);
}

/* ====================================================================== */
/* 3) UDP 트래커 (BEP 15)                                                   */
/* ====================================================================== */

/* 클라이언트 → 트래커 요청. 트래커가 받은 요청의 transaction_id 를 반환 */
static uint32_t udpt_request(int cli, int srv, const struct buf *req, struct sockaddr_in *from)
{
    struct sockaddr_in to = addr_of(TRACKER_PORT);
    uint8_t rx[2048];
    socklen_t fl = sizeof *from;

    if (sendto(cli, req->d, req->n, 0, (struct sockaddr *)&to, sizeof to) < 0) die("sendto");
    ssize_t r = recvfrom(srv, rx, sizeof rx, 0, (struct sockaddr *)from, &fl);
    if (r < 16) fail("UDP 트래커 요청 수신 실패");
    return rd32(rx + 12);
}

/* 트래커 → 클라이언트 응답 */
static void udpt_reply(int cli, int srv, const struct buf *resp, const struct sockaddr_in *to)
{
    uint8_t rx[2048];
    gap();
    if (sendto(srv, resp->d, resp->n, 0, (const struct sockaddr *)to, sizeof *to) < 0) die("sendto");
    if (recv(cli, rx, sizeof rx, 0) < 0) die("recv");
    gap();
}

/* announce 요청 98 bytes */
static void put_udp_announce(struct buf *b, uint64_t cid, uint32_t tid, uint32_t event)
{
    put_u64(b, cid);
    put_u32(b, 1);                 /* action = announce */
    put_u32(b, tid);
    put(b, INFO_HASH, 20);
    put(b, CLIENT_PEER_ID, 20);
    put_u64(b, 0);                 /* downloaded */
    put_u64(b, 163840);            /* left */
    put_u64(b, 0);                 /* uploaded */
    put_u32(b, event);             /* 0 none, 1 completed, 2 started, 3 stopped */
    put_u32(b, 0);                 /* IP 주소 (0 = 보낸 주소 사용) */
    put_u32(b, 0x12345678);        /* key */
    put_u32(b, 0xffffffffu);       /* num_want = -1 (트래커 기본값) */
    put_u16(b, 6881);              /* port */
}

static void test_udp_tracker(void)
{
    struct buf q, r;
    struct sockaddr_in from;
    const uint64_t conn_id = 0x1122334455667788ULL;
    uint8_t c[6];
    uint32_t tid;

    printf("[3/5] UDP 트래커 (127.0.0.1:%d/udp)\n", TRACKER_PORT);
    int srv = udp_socket(TRACKER_PORT);
    int cli = udp_socket(0);

    /* connect: 고정값 0x41727101980 → 트래커가 connection_id 발급 */
    q.n = 0;
    put_u64(&q, UDPT_MAGIC); put_u32(&q, 0); put_u32(&q, 0x0000a001);
    tid = udpt_request(cli, srv, &q, &from);
    r.n = 0;
    put_u32(&r, 0); put_u32(&r, tid); put_u64(&r, conn_id);
    udpt_reply(cli, srv, &r, &from);

    /* announce (event=started) → interval, leechers, seeders, 피어 3개 */
    q.n = 0;
    put_udp_announce(&q, conn_id, 0x0000a002, 2);
    tid = udpt_request(cli, srv, &q, &from);
    r.n = 0;
    put_u32(&r, 1); put_u32(&r, tid);
    put_u32(&r, 1800); put_u32(&r, 3); put_u32(&r, 5);     /* interval, leechers, seeders */
    compact6(c, "127.0.0.1", 6881);  put(&r, c, 6);
    compact6(c, "10.0.0.2", 51413);  put(&r, c, 6);
    compact6(c, "10.0.0.3", 6889);   put(&r, c, 6);
    udpt_reply(cli, srv, &r, &from);

    /* scrape → seeders, completed, leechers */
    q.n = 0;
    put_u64(&q, conn_id); put_u32(&q, 2); put_u32(&q, 0x0000a003); put(&q, INFO_HASH, 20);
    tid = udpt_request(cli, srv, &q, &from);
    r.n = 0;
    put_u32(&r, 2); put_u32(&r, tid);
    put_u32(&r, 5); put_u32(&r, 12); put_u32(&r, 3);
    udpt_reply(cli, srv, &r, &from);

    /* 잘못된 connection_id 로 announce → error 응답 */
    q.n = 0;
    put_udp_announce(&q, 0xdeadbeefULL, 0x0000a004, 0);
    tid = udpt_request(cli, srv, &q, &from);
    r.n = 0;
    put_u32(&r, 3); put_u32(&r, tid); put_text(&r, "Connection ID mismatch");
    udpt_reply(cli, srv, &r, &from);

    close(srv);
    close(cli);
}

/* ====================================================================== */
/* 4) Mainline DHT (BEP 5)                                                  */
/*   질의 키 순서 : a, q, t, (v), y     응답 키 순서 : (ip), r, t, y          */
/* ====================================================================== */

/* 질의 시작: d 1:a d 2:id <노드 A> ... (이어서 인자 추가) */
static void dht_query_begin(struct buf *b)
{
    b->n = 0;
    be_dict(b);
    be_str(b, "a");
    be_dict(b);
    be_str(b, "id"); be_bytes(b, NODE_A, 20);
}

/* 질의 끝: e 1:q <메서드> 1:t <tid> [1:v <버전>] 1:y 1:q e */
static void dht_query_end(struct buf *b, const char *method, const char *tid,
                          const void *ver, size_t verlen)
{
    be_end(b);
    be_str(b, "q"); be_str(b, method);
    be_str(b, "t"); be_str(b, tid);
    if (ver) { be_str(b, "v"); be_bytes(b, ver, verlen); }
    be_str(b, "y"); be_str(b, "q");
    be_end(b);
}

/* 응답 시작: d [2:ip <6 bytes>] 1:r d 2:id <노드 B> ... */
static void dht_resp_begin(struct buf *b, const uint8_t *ip6)
{
    b->n = 0;
    be_dict(b);
    if (ip6) { be_str(b, "ip"); be_bytes(b, ip6, 6); }
    be_str(b, "r");
    be_dict(b);
    be_str(b, "id"); be_bytes(b, NODE_B, 20);
}

/* 응답 끝: e 1:t <tid> 1:y 1:r e */
static void dht_resp_end(struct buf *b, const char *tid)
{
    be_end(b);
    be_str(b, "t"); be_str(b, tid);
    be_str(b, "y"); be_str(b, "r");
    be_end(b);
}

/* 노드 A → B 질의, B → A 응답 */
static void dht_round(int a, int b, const struct buf *q, const struct buf *r)
{
    struct sockaddr_in to_b = addr_of(DHT_PORT_B), to_a = addr_of(DHT_PORT_A);
    uint8_t rx[2048];

    if (sendto(a, q->d, q->n, 0, (struct sockaddr *)&to_b, sizeof to_b) < 0) die("sendto");
    if (recv(b, rx, sizeof rx, 0) < 0) die("recv");
    gap();
    if (sendto(b, r->d, r->n, 0, (struct sockaddr *)&to_a, sizeof to_a) < 0) die("sendto");
    if (recv(a, rx, sizeof rx, 0) < 0) die("recv");
    gap();
}

static void test_dht(void)
{
    static const char token[] = "tok-3team";
    struct buf q, r;
    uint8_t c[6], nodes[52];

    printf("[4/5] DHT (127.0.0.1:%d <-> %d/udp)\n", DHT_PORT_A, DHT_PORT_B);
    int a = udp_socket(DHT_PORT_A);
    int b = udp_socket(DHT_PORT_B);

    /* ping */
    dht_query_begin(&q);
    dht_query_end(&q, "ping", "aa", "LT\x02\x00", 4);          /* v = libtorrent 2.0 */
    compact6(c, HOST, DHT_PORT_A);
    dht_resp_begin(&r, c);                                      /* ip = 상대가 본 내 주소 */
    dht_resp_end(&r, "aa");
    dht_round(a, b, &q, &r);

    /* find_node: 응답의 nodes = (ID 20 + IP 4 + Port 2) x 2 */
    dht_query_begin(&q);
    be_str(&q, "target"); be_bytes(&q, INFO_HASH, 20);
    dht_query_end(&q, "find_node", "bb", NULL, 0);
    memcpy(nodes, NODE_N1, 20);
    compact6(nodes + 20, "10.0.0.11", 6881);
    memcpy(nodes + 26, NODE_N2, 20);
    compact6(nodes + 46, "10.0.0.12", 6882);
    dht_resp_begin(&r, NULL);
    be_str(&r, "nodes"); be_bytes(&r, nodes, sizeof nodes);
    dht_resp_end(&r, "bb");
    dht_round(a, b, &q, &r);

    /* get_peers: 응답에 token 과 피어 목록(values) */
    dht_query_begin(&q);
    be_str(&q, "info_hash"); be_bytes(&q, INFO_HASH, 20);
    dht_query_end(&q, "get_peers", "cc", NULL, 0);
    dht_resp_begin(&r, NULL);
    be_str(&r, "token"); be_str(&r, token);
    be_str(&r, "values");
    be_list(&r);
    compact6(c, "127.0.0.1", 6881); be_bytes(&r, c, 6);
    compact6(c, "10.0.0.2", 51413); be_bytes(&r, c, 6);
    be_end(&r);
    dht_resp_end(&r, "cc");
    dht_round(a, b, &q, &r);

    /* announce_peer: 인자 키 사전순 id, implied_port, info_hash, port, token */
    dht_query_begin(&q);
    be_str(&q, "implied_port"); be_int(&q, 0);
    be_str(&q, "info_hash");    be_bytes(&q, INFO_HASH, 20);
    be_str(&q, "port");         be_int(&q, 6881);
    be_str(&q, "token");        be_str(&q, token);
    dht_query_end(&q, "announce_peer", "dd", NULL, 0);
    dht_resp_begin(&r, NULL);
    dht_resp_end(&r, "dd");
    dht_round(a, b, &q, &r);

    /* info_hash 가 빠진 get_peers → error: d 1:e l i203e <메시지> e 1:t 1:y 1:e e */
    dht_query_begin(&q);
    dht_query_end(&q, "get_peers", "ee", NULL, 0);
    r.n = 0;
    be_dict(&r);
    be_str(&r, "e");
    be_list(&r);
    be_int(&r, 203);
    be_str(&r, "Protocol Error: missing info_hash");
    be_end(&r);
    be_str(&r, "t"); be_str(&r, "ee");
    be_str(&r, "y"); be_str(&r, "e");
    be_end(&r);
    dht_round(a, b, &q, &r);

    close(a);
    close(b);
}

/* ====================================================================== */
/* 5) 암호화 연결 흉내                                                       */
/*   MSE/PE 암호화 연결은 첫 데이터가 DH 공개키(96 bytes, 무작위처럼 보임)라     */
/*   평문 시그니처가 없다.                                                     */
/* ====================================================================== */
static void random_bytes(uint8_t *p, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) die("/dev/urandom");
    if (read(fd, p, n) != (ssize_t)n) die("read /dev/urandom");
    close(fd);
}

static void test_not_plain(void)
{
    uint8_t data[96], rx[96];

    printf("[5/5] 암호화 연결 흉내 (127.0.0.1:%d, 평문 핸드셰이크 없음)\n", PEER_PORT);
    int lfd = tcp_listen(PEER_PORT);
    int cli = tcp_connect(PEER_PORT);
    int srv = tcp_accept(lfd);

    gap();
    random_bytes(data, sizeof data);
    send_all(cli, data, sizeof data);
    recv_exact(srv, rx, sizeof rx);
    gap();
    random_bytes(data, sizeof data);
    send_all(srv, data, sizeof data);
    recv_exact(cli, rx, sizeof rx);
    gap();
    close(cli);
    close(srv);
    close(lfd);
}

/* ====================================================================== */
int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);

    hex_to_bytes(INFO_HASH_HEX, INFO_HASH, 20);
    hex_to_bytes(NODE_A_HEX, NODE_A, 20);
    hex_to_bytes(NODE_B_HEX, NODE_B, 20);
    hex_to_bytes(NODE_N1_HEX, NODE_N1, 20);
    hex_to_bytes(NODE_N2_HEX, NODE_N2, 20);

    printf("BitTorrent 테스트 트래픽 생성 - bt_sniffer 와 Wireshark 를 lo 에서 먼저 실행하세요.\n");
    printf("  Info Hash      : "); print_hex(INFO_HASH, 20); printf("\n");
    printf("  Client Peer ID : %s\n", CLIENT_PEER_ID);
    printf("  Server Peer ID : %s\n", SERVER_PEER_ID);
    printf("  DHT Node A / B : "); print_hex(NODE_A, 20); printf(" / "); print_hex(NODE_B, 20); printf("\n");

    test_peer_wire();
    sleep_ms(500);
    test_http_tracker();
    sleep_ms(500);
    test_udp_tracker();
    sleep_ms(500);
    test_dht();
    sleep_ms(500);
    test_not_plain();
    printf("완료\n");
    return 0;
}
