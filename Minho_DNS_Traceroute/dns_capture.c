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
    UDP_HEADER_SIZE = 8,
    DNS_HEADER_SIZE = 12,
    DNS_PORT = 53,
    DNS_TYPE_A = 1,
    DNS_CLASS_IN = 1,
    DNS_NAME_CAPACITY = 254,
    DNS_RR_FIELDS_SIZE = 10
};

typedef struct {
    const uint8_t *source_ip;
    const uint8_t *destination_ip;
    unsigned source_port;
    unsigned destination_port;
    const uint8_t *payload;
    size_t payload_length;
} UdpPacket;

typedef struct {
    unsigned transaction_id;
    unsigned qr;
    unsigned question_count;
    unsigned answer_count;
} DnsHeader;

static unsigned read_u16(const uint8_t *bytes)
{
    return ((unsigned)bytes[0] << 8) | bytes[1];
}

static bool decode_udp(const uint8_t *frame, size_t length, UdpPacket *packet)
{
    if (length < ETHERNET_HEADER_SIZE + IPV4_MIN_HEADER_SIZE ||
        read_u16(frame + 12) != ETH_P_IP)
        return false;

    const uint8_t *ip = frame + ETHERNET_HEADER_SIZE;
    size_t header_length = (ip[0] & 0x0fu) * 4u;
    size_t total_length = read_u16(ip + 2);

    if ((ip[0] >> 4) != 4 || ip[9] != IPPROTO_UDP ||
        header_length < IPV4_MIN_HEADER_SIZE ||
        total_length < header_length + UDP_HEADER_SIZE ||
        total_length > length - ETHERNET_HEADER_SIZE ||
        (read_u16(ip + 6) & 0x3fffu) != 0)
        return false;

    const uint8_t *udp = ip + header_length;
    size_t udp_length = read_u16(udp + 4);

    if (udp_length < UDP_HEADER_SIZE ||
        udp_length > total_length - header_length)
        return false;

    *packet = (UdpPacket){
        .source_ip = ip + 12,
        .destination_ip = ip + 16,
        .source_port = read_u16(udp),
        .destination_port = read_u16(udp + 2),
        .payload = udp + UDP_HEADER_SIZE,
        .payload_length = udp_length - UDP_HEADER_SIZE
    };
    return true;
}

static bool is_dns_exchange(const UdpPacket *packet, bool outgoing)
{
    const uint8_t server_ip[] = {1, 1, 1, 1};
    const uint8_t *remote_ip =
        outgoing ? packet->destination_ip : packet->source_ip;
    unsigned remote_port =
        outgoing ? packet->destination_port : packet->source_port;

    return remote_port == DNS_PORT &&
           memcmp(remote_ip, server_ip, sizeof(server_ip)) == 0;
}

static bool decode_dns_header(const UdpPacket *packet, DnsHeader *header)
{
    if (packet->payload_length < DNS_HEADER_SIZE)
        return false;

    const uint8_t *message = packet->payload;
    *header = (DnsHeader){
        .transaction_id = read_u16(message),
        .qr = (message[2] >> 7) & 1u,
        .question_count = read_u16(message + 4),
        .answer_count = read_u16(message + 6)
    };
    return true;
}

static bool decode_dns_name(const uint8_t *message, size_t length,
                            size_t *offset, char name[DNS_NAME_CAPACITY])
{
    size_t cursor = *offset;
    size_t limit = length;
    size_t resume = 0;
    size_t written = 0;

    while (cursor < limit) {
        size_t marker = cursor;
        unsigned label_length = message[cursor++];

        if (label_length == 0) {
            if (written == 0)
                name[written++] = '.';

            name[written] = '\0';
            *offset = resume == 0 ? cursor : resume;
            return true;
        }

        if ((label_length & 0xc0u) == 0xc0u) {
            if (cursor == limit)
                return false;

            size_t target = ((label_length & 0x3fu) << 8) | message[cursor++];
            if (target < DNS_HEADER_SIZE || target >= marker)
                return false;

            /* 호출자는 원래 위치에서 포인터 2바이트 다음부터 읽는다. */
            if (resume == 0)
                resume = cursor;

            /* 이전 이름만 읽도록 범위를 줄여 순환 참조를 막는다. */
            limit = marker;
            cursor = target;
            continue;
        }

        size_t separator = (written > 0);
        if (label_length > 63 || label_length > limit - cursor ||
            written + separator + label_length >= DNS_NAME_CAPACITY)
            return false;

        if (separator)
            name[written++] = '.';

        for (unsigned i = 0; i < label_length; i++) {
            uint8_t byte = message[cursor++];
            name[written++] = (byte >= 33 && byte <= 126) ? (char)byte : '?';
        }
    }

    return false;
}

static void print_dns_sections(const UdpPacket *packet, const DnsHeader *dns)
{
    const uint8_t *message = packet->payload;
    size_t length = packet->payload_length;
    size_t offset = DNS_HEADER_SIZE;
    char name[DNS_NAME_CAPACITY];

    for (unsigned i = 0; i < dns->question_count; i++) {
        if (!decode_dns_name(message, length, &offset, name) ||
            length - offset < 4)
            return;

        unsigned type = read_u16(message + offset);
        printf("     QNAME=%s | QTYPE=%u%s\n",
               name, type, type == DNS_TYPE_A ? " (A)" : "");
        offset += 4; /* QTYPE 2바이트 + QCLASS 2바이트 */
    }

    if (dns->qr == 0)
        return;

    for (unsigned i = 0; i < dns->answer_count; i++) {
        if (!decode_dns_name(message, length, &offset, name) ||
            length - offset < DNS_RR_FIELDS_SIZE)
            return;

        unsigned type = read_u16(message + offset);
        unsigned record_class = read_u16(message + offset + 2);
        size_t data_length = read_u16(message + offset + 8);
        offset += DNS_RR_FIELDS_SIZE; /* TYPE, CLASS, TTL, RDLENGTH */

        if (data_length > length - offset)
            return;

        if (type == DNS_TYPE_A && record_class == DNS_CLASS_IN &&
            data_length == 4) {
            char address[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, message + offset, address,
                          sizeof(address)) != NULL)
                printf("     A %s -> %s\n", name, address);
        }

        offset += data_length;
    }
}

static void print_packet(const UdpPacket *packet, bool outgoing)
{
    DnsHeader dns;
    if (!decode_dns_header(packet, &dns))
        return;

    char source[INET_ADDRSTRLEN];
    char destination[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, packet->source_ip, source, sizeof(source)) == NULL ||
        inet_ntop(AF_INET, packet->destination_ip, destination,
                  sizeof(destination)) == NULL) {
        perror("inet_ntop");
        return;
    }

    printf("[%s] %s:%u -> %s:%u | UDP payload %zu bytes\n",
           outgoing ? "TX" : "RX", source, packet->source_port,
           destination, packet->destination_port, packet->payload_length);
    printf("     ID=%u | QR=%u (%s)\n",
           dns.transaction_id, dns.qr, dns.qr == 0 ? "Query" : "Response");

    print_dns_sections(packet, &dns);
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

    printf("Listening on %s for UDP traffic to/from 1.1.1.1:53\n", interface);

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

        UdpPacket packet;
        bool outgoing = metadata.sll_pkttype == PACKET_OUTGOING;
        if (decode_udp(frame, (size_t)length, &packet) &&
            is_dns_exchange(&packet, outgoing))
            print_packet(&packet, outgoing);
    }
}
