#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum { ETH_SIZE = 14, IP_MIN = 20, UDP_SIZE = 8, ICMP_SIZE = 8,
       FIRST_PORT = 33434, LAST_PORT = 33534, PROBE_CAPACITY = 128 };
static const uint8_t target_ip[] = {1, 1, 1, 1};

typedef struct {
    uint8_t local_ip[4];
    unsigned src_port, dst_port, ttl;
} Probe;

static unsigned read_u16(const uint8_t *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}

/* ICMP 오류에는 원래 IP 패킷의 앞부분만 포함될 수 있다. */
static size_t ip_header_size(const uint8_t *ip, size_t available)
{
    if (available < IP_MIN || ip[0] >> 4 != 4)
        return 0;
    size_t size = (ip[0] & 15u) * 4u;
    if (size < IP_MIN || size > available || read_u16(ip + 2) < size ||
        (read_u16(ip + 6) & 0x3fffu) != 0)
        return 0;
    return size;
}

static void inspect_frame(const uint8_t *frame, size_t length, bool outgoing,
                          Probe probes[], size_t *next)
{
    if (length < ETH_SIZE || read_u16(frame + 12) != ETH_P_IP)
        return;
    const uint8_t *ip = frame + ETH_SIZE;
    size_t available = length - ETH_SIZE;
    size_t header = ip_header_size(ip, available);
    if (!header || read_u16(ip + 2) > available)
        return;
    size_t payload_size = read_u16(ip + 2) - header;
    const uint8_t *payload = ip + header;
    if (outgoing) {
        if (ip[9] != IPPROTO_UDP || memcmp(ip + 16, target_ip, 4) ||
            payload_size < UDP_SIZE)
            return;
        unsigned src = read_u16(payload), dst = read_u16(payload + 2);
        unsigned udp_length = read_u16(payload + 4);
        if (dst < FIRST_PORT || dst > LAST_PORT ||
            udp_length < UDP_SIZE || udp_length > payload_size)
            return;
        Probe *probe = &probes[*next];
        memcpy(probe->local_ip, ip + 12, 4);
        probe->src_port = src;
        probe->dst_port = dst;
        probe->ttl = ip[8];
        *next = (*next + 1) % PROBE_CAPACITY;
        printf("[TX] dst=1.1.1.1 | IPv4 TTL=%u | UDP %u -> %u\n",
               probe->ttl, src, dst);
        return;
    }

    if (ip[9] != IPPROTO_ICMP || payload_size < ICMP_SIZE)
        return;
    unsigned type = payload[0], code = payload[1];
    bool expired = type == 11 && code == 0;
    bool port_closed = type == 3 && code == 3;
    if (!expired && !port_closed)
        return;

    const uint8_t *inner = payload + ICMP_SIZE;
    size_t quoted_size = payload_size - ICMP_SIZE;
    size_t inner_header = ip_header_size(inner, quoted_size);
    if (!inner_header || quoted_size - inner_header < UDP_SIZE ||
        read_u16(inner + 2) < inner_header + UDP_SIZE ||
        inner[9] != IPPROTO_UDP || memcmp(inner + 16, target_ip, 4) ||
        memcmp(inner + 12, ip + 16, 4))
        return;
    const uint8_t *udp = inner + inner_header;
    unsigned src = read_u16(udp), dst = read_u16(udp + 2);
    for (size_t age = 1; age <= PROBE_CAPACITY; ++age) {
        const Probe *probe = &probes[(*next + PROBE_CAPACITY - age) % PROBE_CAPACITY];
        if (!probe->ttl || probe->src_port != src || probe->dst_port != dst ||
            memcmp(probe->local_ip, inner + 12, 4))
            continue;
        char router[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, ip + 12, router, sizeof(router)))
            return;
        printf("[RX] src=%s | ICMP Type=%u Code=%u (%s) | quoted UDP %u -> %u | Probe TTL=%u\n",
               router, type, code, expired ? "Time Exceeded" : "Port Unreachable",
               src, dst, probe->ttl);
        return;
    }
}

int main(void)
{
    const char *interface = "eth0";
    unsigned index = if_nametoindex(interface);
    if (index == 0) {
        perror("if_nametoindex");
        return 1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_ll binding = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex = (int)index
    };

    if (bind(fd, (struct sockaddr *)&binding, sizeof(binding)) == -1) {
        perror("bind");
        close(fd);
        return 1;
    }

    printf("Listening on %s for UDP traceroute to 1.1.1.1\n", interface);

    Probe probes[PROBE_CAPACITY] = {0};
    size_t next_slot = 0;
    uint8_t frame[65536];

    for (;;) {
        struct sockaddr_ll metadata = {0};
        socklen_t metadata_length = sizeof(metadata);
        ssize_t length = recvfrom(fd, frame, sizeof(frame), 0,
                                  (struct sockaddr *)&metadata, &metadata_length);

        if (length == -1) {
            perror("recvfrom");
            close(fd);
            return 1;
        }

        inspect_frame(frame, (size_t)length, metadata.sll_pkttype == PACKET_OUTGOING,
                      probes, &next_slot);
    }
}
