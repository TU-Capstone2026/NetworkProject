"""tcpdump 로 저장한 pcap 을 따로 분석해 bt_sniffer 통계를 검증한다 (Python 표준 라이브러리만 사용).

1) TCP 스트림을 방향별로 Seq 순서대로 재조립하고, 평문 BitTorrent 핸드셰이크("\\x13BitTorrent protocol")를
   스트림 앞부분(2000바이트 안)에서 찾는다. MSE 협상 뒤에 평문 핸드셰이크가 오는 경우도 찾는다.
2) 핸드셰이크 뒤의 Peer Wire 메시지를 종류별로 센다. 캡처에 빠진 구간이 있으면 그 앞까지만 센다.
3) 상대별 수신 데이터 양을 평문 BitTorrent 연결 / 평문 핸드셰이크가 없는 연결로 나눠 보여 준다.
   (처음부터 암호화된 BitTorrent 연결이 얼마나 되는지 가늠할 때 쓴다)

사용법
  python3 scripts/verify_pcap.py captures/bt_real.pcap
  python3 scripts/verify_pcap.py captures/bt_lo.pcap

지원 형식: 기존 pcap (pcapng 아님), 링크 타입 Ethernet(1) · Linux cooked(113), IPv4
"""
import argparse
import socket
import struct
import sys
from collections import Counter, defaultdict

NAMES = {0: "Choke", 1: "Unchoke", 2: "Interested", 3: "Not Interested", 4: "Have",
         5: "Bitfield", 6: "Request", 7: "Piece", 8: "Cancel", 9: "Port",
         13: "Suggest", 14: "Have All", 15: "Have None", 16: "Reject", 17: "Allowed Fast", 20: "Extended"}
HANDSHAKE = b"\x13BitTorrent protocol"


def read_packets(path):
    """(링크 타입, 패킷 바이트)를 차례로 돌려준다."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            sys.exit("pcap 헤더가 없습니다")
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            en = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            en = ">"
        elif magic == b"\x0a\x0d\x0d\x0a":
            sys.exit("pcapng 는 지원하지 않습니다. tcpdump -w 로 저장한 pcap 을 쓰거나 Wireshark 에서 pcap 으로 저장하세요")
        else:
            sys.exit("pcap 파일이 아닙니다")
        linktype = struct.unpack(en + "I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            incl = struct.unpack(en + "IIII", ph)[2]
            yield linktype, f.read(incl)


def ipv4_tcp(linktype, pkt):
    """IPv4/TCP 면 (src, sport, dst, dport, seq, flags, payload) 를, 아니면 None."""
    if linktype == 1:
        off = 14
        etype = pkt[12:14]
        if etype == b"\x81\x00":            # VLAN 태그
            etype, off = pkt[16:18], 18
    elif linktype == 113:
        off, etype = 16, pkt[14:16]
    else:
        sys.exit(f"지원하지 않는 링크 타입입니다: {linktype}")
    if etype != b"\x08\x00" or len(pkt) < off + 20:
        return None
    ip = pkt[off:]
    ihl = (ip[0] & 15) * 4
    if ip[9] != 6 or len(ip) < ihl + 20:
        return None
    tot = struct.unpack("!H", ip[2:4])[0] or len(ip)    # offload 로 0 이 기록된 경우 실제 길이 사용
    tcp = ip[ihl:tot]
    sp, dp, seq = struct.unpack("!HHI", tcp[:8])
    doff = (tcp[12] >> 4) * 4
    return socket.inet_ntoa(ip[12:16]), sp, socket.inet_ntoa(ip[16:20]), dp, seq, tcp[13], tcp[doff:]


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="pcap 으로 bt_sniffer 통계 검증")
    ap.add_argument("pcap")
    ap.add_argument("--top", type=int, default=10, help="수신량 상위 몇 개 상대를 보여 줄지")
    args = ap.parse_args()

    flows = defaultdict(lambda: {"isn": None, "segs": {}})
    frames = 0
    for lt, pkt in read_packets(args.pcap):
        frames += 1
        r = ipv4_tcp(lt, pkt)
        if not r:
            continue
        src, sp, dst, dp, seq, flags, payload = r
        fl = flows[(src, sp, dst, dp)]
        if flags & 0x02:                    # SYN, SYN+ACK
            fl["isn"] = seq
        if payload and len(payload) > len(fl["segs"].get(seq, b"")):
            fl["segs"][seq] = payload       # 같은 Seq 재전송은 가장 긴 것 하나만

    total = Counter()
    piece_bytes = 0
    bt_flows = set()
    streams = []
    recv = Counter()
    for key, fl in flows.items():
        if not fl["segs"]:
            continue
        recv[key] += sum(len(p) for p in fl["segs"].values())
        if fl["isn"] is None:           # SYN 을 못 본 연결은 재조립하지 않음
            continue
        base = (fl["isn"] + 1) & 0xFFFFFFFF
        data, gap_at = bytearray(), None
        for seq in sorted(fl["segs"], key=lambda s: (s - base) & 0xFFFFFFFF):
            rel = (seq - base) & 0xFFFFFFFF
            p = fl["segs"][seq]
            if rel > len(data):
                if gap_at is None:
                    gap_at = len(data)
                data += bytes(rel - len(data))
            if rel + len(p) > len(data):
                data += p[len(data) - rel:]
        hs = data.find(HANDSHAKE, 0, 2000)
        if hs < 0:
            continue
        bt_flows.add(key)
        stop = gap_at if gap_at is not None else len(data)
        streams.append((key, len(data), hs, stop))
        i = hs + 68
        while i + 4 <= stop:
            ln = struct.unpack("!I", data[i:i + 4])[0]
            if ln == 0:
                total["Keep-Alive"] += 1
                i += 4
                continue
            if i + 4 + ln > stop:
                break
            mid = data[i + 4]
            total[NAMES.get(mid, f"id{mid}")] += 1
            if mid == 7:
                piece_bytes += ln - 9
            i += 4 + ln

    print(f"파일: {args.pcap}  (전체 프레임 {frames})")
    print(f"\n[1] 평문 핸드셰이크가 있는 TCP 스트림 (방향별) {len(streams)}개")
    for (src, sp, dst, dp), ln, hs, stop in sorted(streams, key=lambda x: -x[1]):
        note = "" if stop == ln else f", 캡처에 빠진 구간이 있어 {stop} bytes 까지만 셈"
        print(f"  {src}:{sp} -> {dst}:{dp}  {ln} bytes, 핸드셰이크 앞 {hs} bytes{note}")

    print("\n[2] Peer Wire 메시지 수 (bt_sniffer 통계의 'Peer Wire 메시지' 와 비교)")
    for name, n in total.most_common():
        print(f"  {name:15s} {n}")
    print(f"  piece 데이터 합계: {piece_bytes} bytes")

    print(f"\n[3] 상대 → 나 수신 데이터 상위 {args.top} (재전송 제외)")
    by_peer = Counter()
    kinds = {}
    for key, n in recv.items():
        src, sp, dst, dp = key
        if src.startswith(("10.", "192.168.", "127.")) or src.startswith(tuple(f"172.{i}." for i in range(16, 32))):
            continue        # 내 쪽에서 보낸 방향 제외
        by_peer[(src, sp)] += n
        rev = (dst, dp, src, sp)
        kinds[(src, sp)] = "평문 BT" if key in bt_flows or rev in bt_flows else "평문 핸드셰이크 없음"
    for (ip, port), n in by_peer.most_common(args.top):
        print(f"  {ip:>15}:{port:<5}  {n / 1e6:8.2f} MB  {kinds[(ip, port)]}")
    sums = Counter()
    for k, n in by_peer.items():
        sums[kinds[k]] += n
    all_bytes = sum(by_peer.values()) or 1
    for k in ("평문 BT", "평문 핸드셰이크 없음"):
        print(f"  합계 {k:12s} {sums[k] / 1e6:8.2f} MB ({sums[k] * 100 / all_bytes:.0f}%)")
    print("  ※ '평문 핸드셰이크 없음' 에는 처음부터 암호화된 BT 연결과 트래커·HTTPS 같은 다른 TCP 가 섞여 있습니다.")


if __name__ == "__main__":
    main()
