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

enum {
    ETHERNET_HEADER_SIZE = 14,
    IPV4_MIN_HEADER_SIZE = 20,
    ICMP_HEADER_SIZE = 8,
    ICMP_ECHO_REPLY = 0,
    ICMP_ECHO_REQUEST = 8,
    ICMP_TIME_EXCEEDED = 11,
    PROBE_CAPACITY = 128
};

static const uint8_t target_ip[] = {1, 1, 1, 1};

typedef struct {
    const uint8_t *source_ip;
    const uint8_t *destination_ip;
    const uint8_t *icmp;
    size_t icmp_length;
    unsigned ttl;
} IcmpPacket;

typedef struct {
    uint8_t local_ip[4];
    unsigned id;
    unsigned sequence;
    unsigned ttl;
} Probe;

static unsigned read_u16(const uint8_t *bytes)
{
    return ((unsigned)bytes[0] << 8) | bytes[1];
}

static bool decode_ipv4_icmp(const uint8_t *frame, size_t length,
                             IcmpPacket *packet)
{
    if (length < ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE ||
        read_u16(frame + 12) != ETH_P_IP)
        return false;

    const uint8_t *ip = frame + ETHERNET_HEADER_SIZE;
    size_t header_length = (ip[0] & 0x0fu) * 4u;
    size_t total_length = read_u16(ip + 2);

    if ((ip[0] >> 4) != 4 || ip[9] != IPPROTO_ICMP ||
        header_length < IPV4_MIN_HEADER_SIZE ||
        total_length < header_length + ICMP_HEADER_SIZE ||
        total_length > length - ETHERNET_HEADER_SIZE ||
        (read_u16(ip + 6) & 0x3fffu) != 0)
        return false;

    *packet = (IcmpPacket){
        .source_ip = ip + 12,
        .destination_ip = ip + 16,
        .icmp = ip + header_length,
        .icmp_length = total_length - header_length,
        .ttl = ip[8]
    };
    return true;
}

static void record_probe(const IcmpPacket *packet, Probe *slot)
{
    memcpy(slot->local_ip, packet->source_ip, sizeof(slot->local_ip));
    slot->id = read_u16(packet->icmp + 4);
    slot->sequence = read_u16(packet->icmp + 6);
    slot->ttl = packet->ttl;

    printf("[TX] dst=1.1.1.1 | IPv4 TTL=%u | Type=8 Code=0 | ID=%u Seq=%u\n",
           slot->ttl, slot->id, slot->sequence);
}

static const uint8_t *quoted_echo_request(const IcmpPacket *packet)
{
    const uint8_t *ip = packet->icmp + ICMP_HEADER_SIZE;
    size_t length = packet->icmp_length - ICMP_HEADER_SIZE;

    if (length < IPV4_MIN_HEADER_SIZE || (ip[0] >> 4) != 4 ||
        ip[9] != IPPROTO_ICMP ||
        memcmp(ip + 16, target_ip, sizeof(target_ip)) != 0 ||
        memcmp(ip + 12, packet->destination_ip, sizeof(target_ip)) != 0)
        return NULL;

    size_t header_length = (ip[0] & 0x0fu) * 4u;
    if (header_length < IPV4_MIN_HEADER_SIZE ||
        length < header_length + ICMP_HEADER_SIZE ||
        (read_u16(ip + 6) & 0x1fffu) != 0)
        return NULL;

    const uint8_t *echo = ip + header_length;
    if (echo[0] != ICMP_ECHO_REQUEST || echo[1] != 0)
        return NULL;

    return echo;
}

static unsigned find_probe_ttl(const Probe probes[], size_t next_slot,
                               const uint8_t *local_ip, unsigned id,
                               unsigned sequence)
{
    /* 최근에 기록한 송신 패킷부터 찾는다. TTL 0은 빈 슬롯이다. */
    for (size_t age = 1; age <= PROBE_CAPACITY; age++) {
        size_t index = (next_slot + PROBE_CAPACITY - age) % PROBE_CAPACITY;
        const Probe *probe = &probes[index];

        if (probe->ttl != 0 && probe->id == id &&
            probe->sequence == sequence &&
            memcmp(probe->local_ip, local_ip, sizeof(probe->local_ip)) == 0)
            return probe->ttl;
    }
    return 0;
}

static void print_response(const IcmpPacket *packet, const Probe probes[],
                           size_t next_slot)
{
    unsigned type = packet->icmp[0];
    unsigned code = packet->icmp[1];
    const uint8_t *echo;
    const char *description;

    if (type == ICMP_TIME_EXCEEDED && code == 0) {
        echo = quoted_echo_request(packet);
        if (echo == NULL)
            return;
        description = "Time Exceeded";
    } else if (type == ICMP_ECHO_REPLY && code == 0 &&
               memcmp(packet->source_ip, target_ip, sizeof(target_ip)) == 0) {
        echo = packet->icmp;
        description = "Echo Reply";
    } else {
        return;
    }

    unsigned id = read_u16(echo + 4);
    unsigned sequence = read_u16(echo + 6);
    unsigned ttl = find_probe_ttl(probes, next_slot, packet->destination_ip,
                                  id, sequence);

    char source[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, packet->source_ip, source, sizeof(source)) == NULL)
        return;

    printf("[RX] src=%s | Type=%u Code=%u (%s) | ID=%u Seq=%u",
           source, type, code, description, id, sequence);
    if (ttl != 0)
        printf(" | Probe TTL=%u\n", ttl);
    else
        puts(" | Probe TTL=?");
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

    printf("Listening on %s for ICMP traceroute to 1.1.1.1\n", interface);

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

        IcmpPacket packet;
        if (!decode_ipv4_icmp(frame, (size_t)length, &packet))
            continue;

        if (metadata.sll_pkttype == PACKET_OUTGOING) {
            if (packet.icmp[0] == ICMP_ECHO_REQUEST && packet.icmp[1] == 0 &&
                memcmp(packet.destination_ip, target_ip, sizeof(target_ip)) == 0) {
                record_probe(&packet, &probes[next_slot]);
                next_slot = (next_slot + 1) % PROBE_CAPACITY;
            }
        } else {
            print_response(&packet, probes, next_slot);
        }
    }
}
