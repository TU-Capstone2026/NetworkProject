/*
 * bittorrent.h - BitTorrent 응용 계층 분석 모듈
 *
 *   분석 대상
 *     [TCP] Peer Wire Protocol (BEP 3)  : 핸드셰이크, 메시지(choke ~ piece, extended)
 *     [TCP] HTTP Tracker (BEP 3)        : announce / scrape 요청, bencode 응답
 *     [UDP] UDP Tracker (BEP 15)        : connect / announce / scrape / error
 *     [UDP] Mainline DHT (BEP 5)        : ping, find_node, get_peers, announce_peer
 *
 *   반환값: BitTorrent 로 판별해서 출력했으면 1, 아니면 0
 */
#ifndef BITTORRENT_H
#define BITTORRENT_H

#include "common.h"

void bt_init(int verbose, const uint16_t *ports, int nports);
int  bt_analyze_tcp(const struct pkt_info *pi);
int  bt_analyze_udp(const struct pkt_info *pi);
void bt_print_stats(void);

#endif /* BITTORRENT_H */
