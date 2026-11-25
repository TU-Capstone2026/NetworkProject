# BitTorrent 패킷 분석기 (bt_sniffer)

컴퓨터네트워크 설계 3팀 · BitTorrent 담당 류상진
Linux · C · Raw Socket(AF_PACKET / SOCK_RAW)

네트워크 인터페이스에서 **송신·수신 패킷을 모두 캡처**하고, IP / TCP / UDP 헤더와 BitTorrent 응용 계층(Peer Wire, 트래커, DHT)을 해석해서 출력합니다.

---

## 1. 파일 구성

| 파일 | 역할 |
|---|---|
| `main.c` | Raw Socket 생성, 캡처 루프, 송수신 구분, Ethernet → IPv4 → TCP/UDP 헤더 해석, 공통 출력, 통계 |
| `common.h` | 패킷 정보 구조체 `struct pkt_info` (나중에 팀 공용 레포에 합칠 때 이 형식만 맞추면 됨) |
| `bittorrent.c / .h` | BitTorrent 분석 모듈 (핸드셰이크, 메시지, HTTP/UDP 트래커, DHT) |
| `bencode.c / .h` | BitTorrent 데이터 형식(bencode) 파서 |
| `Makefile` | 빌드 |
| `test/bt_testgen.py` | 루프백 테스트 트래픽 생성기 (Python 3 기본 라이브러리만 사용) |
| `docs/sample_output_lo.txt` | 루프백 테스트 실제 출력 결과 |

## 2. 빌드

```bash
sudo apt install build-essential     # gcc, make 가 없을 때만
make                                 # → ./bt_sniffer 생성
```

## 3. 실행 옵션

```
sudo ./bt_sniffer [-i 인터페이스] [-p 포트] [-a] [-v] [-d] [-c 개수]
  -i IFACE  캡처할 인터페이스 (lo, eth0, enp0s3, wlan0 ...). 생략하면 전체
  -p PORT   BitTorrent 클라이언트 리슨 포트 (6881~6889 는 기본 포함)
  -a        BitTorrent 가 아닌 TCP/UDP 패킷도 한 줄 요약으로 출력
  -v        상세 출력 (piece 데이터 이어짐, 재전송, 순수 ACK 포함)
  -d        lo 에서 같은 패킷이 송신/수신으로 두 번 잡히는 것을 한 번만 출력
  -c N      BitTorrent 패킷 N개를 출력하면 종료
  Ctrl+C    종료 → 캡처 통계 출력
```

- Raw Socket 은 root 권한이 필요하므로 **반드시 `sudo`** 로 실행합니다.
- 결과를 파일로 남기려면 `| tee 결과.txt` 를 붙입니다. 출력은 줄 단위로 바로 저장됩니다.

---

## 4. 캡처 방법

### 4-1. 루프백 테스트 (먼저 이것부터, 매번 같은 결과)

실제 토렌트 없이 값이 정해진 BitTorrent 패킷을 `127.0.0.1` 로 주고받습니다. 보고서 캡처화면과 Wireshark 대조용으로 가장 확실합니다.

```bash
# 터미널 1 - 분석기
sudo ./bt_sniffer -i lo -d | tee result_lo.txt

# 터미널 2 - Wireshark (선택) : Loopback: lo 선택 후 캡처 시작
sudo wireshark            # GUI 가 없으면: sudo tcpdump -i lo -w bt_lo.pcap

# 터미널 3 - 테스트 트래픽 발생 (sudo 필요 없음)
python3 test/bt_testgen.py
```

끝나면 터미널 1 에서 `Ctrl+C` 를 누릅니다. 발생하는 트래픽은 다음과 같습니다.

| 순서 | 내용 | 확인할 수 있는 것 |
|---|---|---|
| 1 | TCP 6881 Peer Wire | 3-way handshake, 핸드셰이크(Info Hash, Peer ID), bitfield, 확장 핸드셰이크, interested → unchoke → request → piece(5개 세그먼트로 나뉨), 두 세그먼트로 쪼개진 have, port, request+cancel, keep-alive, choke, FIN 연결 해제 |
| 2 | TCP 6969 HTTP 트래커 | announce 요청 파라미터, bencode 응답(interval, 시더/리처 수, 피어 목록) |
| 3 | UDP 6969 UDP 트래커 | connect → announce → scrape, 잘못된 connection_id → error |
| 4 | UDP 6881↔6882 DHT | ping, find_node, get_peers, announce_peer, error |
| 5 | TCP 6881 암호화 흉내 | 평문 핸드셰이크 없이 무작위 바이트만 오가는 연결 → "평문 핸드셰이크 아님" 경고 |

> **lo 에서 `-d` 를 쓰는 이유:** 루프백은 커널이 같은 패킷을 "송신 사본"과 "수신 사본"으로 두 번 넘겨줍니다. `-d` 없이 실행하면 모든 패킷이 `[송신]`, `[수신]` 으로 두 번씩 나옵니다. 송수신을 둘 다 잡는다는 걸 보여줄 때는 오히려 `-d` 없이 찍는 것도 좋습니다. Wireshark 는 lo 에서 한 번만 보여주므로, 개수를 비교할 때는 `-d` 를 씁니다.

### 4-2. 실제 BitTorrent 트래픽

합법적인 리눅스 배포판 토렌트를 사용합니다. **Debian netinst** 를 추천합니다. 공식 트래커가 평문 HTTP(`http://bttracker.debian.org:6969/announce`)라 트래커 요청·응답 내용까지 볼 수 있습니다.

1. `.torrent` 받기: `https://cdimage.debian.org/debian-cd/current/amd64/bt-cd/` 에서 `debian-…-amd64-netinst.iso.torrent`
2. 인터페이스 이름 확인: `ip -br a` (VirtualBox 는 보통 `enp0s3`, 유선 `eth0`/`enpXsY`, 무선 `wlan0`/`wlpXsY`)
3. **분석기를 먼저 켜고** 토렌트를 시작합니다. 핸드셰이크는 연결 시작 순간에만 오기 때문입니다.

**방법 A - aria2c (명령줄, 가장 간단)**

aria2 는 피어 연결에 TCP 만 사용하고, DHT 와 UDP 트래커도 기본으로 켜져 있습니다.

```bash
sudo apt install aria2

# 터미널 1
sudo ./bt_sniffer -i enp0s3 -p 6881 | tee result_real.txt

# 터미널 2
aria2c --listen-port=6881 --dht-listen-port=6881 --disable-ipv6=true \
       --bt-require-crypto=false --seed-time=0 debian-*-amd64-netinst.iso.torrent
```

1~2분 정도 받다가 `Ctrl+C` 로 멈춰도 핸드셰이크, 메시지, 트래커, DHT 가 충분히 잡힙니다.

**방법 B - qBittorrent (GUI)**

메뉴 이름은 버전·언어에 따라 조금 다를 수 있습니다.
- 도구 → 옵션 → 연결: 피어 연결 프로토콜 = **TCP** (uTP 끄기), 수신 포트 = **6881** 고정
- 도구 → 옵션 → BitTorrent: 암호화 모드 = **암호화 사용 안 함 (Disable encryption)**
- 실행: `sudo ./bt_sniffer -i <인터페이스> -p 6881`

**실제 트래픽에서 주의할 점**
- **핸드셰이크 대신 "평문 핸드셰이크 아님"만 보이면** 암호화(MSE/PE) 연결입니다. 클라이언트는 보통 암호화를 먼저 시도하고, 상대가 암호화를 요구하면 평문으로는 연결되지 않습니다. 피어가 여러 명이면 그중 일부만 평문입니다.
- **학교·기숙사망은 P2P 를 막는 경우가 많습니다.** 트래커 요청만 보이고 피어 연결이 안 되면 다른 네트워크(예: 휴대폰 핫스팟)에서 테스트합니다.
- **VM(NAT)** 에서는 외부 피어가 먼저 접속해 올 수 없습니다. 그래도 내가 먼저 거는 연결(송신 핸드셰이크 → 수신 핸드셰이크)은 정상적으로 보입니다.
- IPv6 피어는 분석하지 않으므로 aria2 에 `--disable-ipv6=true` 를 넣었습니다.

### 4-3. WSL2 에서 할 때 (기본 NAT 네트워크 기준)

- WSL2 는 실제 리눅스 커널이라 AF_PACKET Raw Socket 이 `sudo` 로 동작합니다. 루프백 테스트(4-1)는 그대로 됩니다.
- WSL 의 `eth0` 에는 WSL 안의 프로그램 트래픽만 보입니다. 그래서 실제 토렌트는 Windows 의 qBittorrent 가 아니라 **WSL 안에서 aria2c** 로 실행합니다.
- Windows 의 Wireshark 로는 WSL 의 lo 가 안 보입니다. WSL 안에서 저장한 뒤 Windows 에서 엽니다.
  ```bash
  sudo apt install tcpdump
  sudo tcpdump -i lo -w /mnt/c/Users/<윈도우사용자명>/Desktop/bt_lo.pcap
  ```

### 4-4. Wireshark 와 대조하는 방법

- 분석기와 Wireshark 로 **같은 인터페이스를 동시에** 캡처합니다.
- 디스플레이 필터: `bittorrent || bt-dht || bt-tracker || http.request.uri contains "info_hash"`
- **Seq/Ack:** Wireshark 는 기본으로 상대 번호(1, 2, …)를 보여줍니다. 이 프로그램은 실제 값(raw)을 출력하므로 TCP 항목의 `Sequence Number (raw)` 와 비교합니다. 또는 편집 → 설정 → Protocols → TCP → *Relative sequence numbers* 를 끕니다.
- 포트가 6881~6889 가 아니면 Wireshark 가 BitTorrent 로 표시하지 않을 수 있습니다. 이때는 패킷 우클릭 → *Decode As…* → BitTorrent 를 지정합니다.
- UDP 트래커의 Transaction ID 를 Wireshark 는 10진수로 보여줍니다. 이 프로그램은 `0x0000a001 (40961)` 처럼 둘 다 출력합니다.

**직접 대조한 결과 (tshark 4.2.2, 루프백 테스트)**
- 일치: TCP Seq/Ack raw 값, 핸드셰이크 Info Hash·Peer ID, 메시지 종류 순서(bitfield+extended / interested / unchoke / request / piece / have / port / request+cancel / keep-alive / not interested / choke), request·have 의 index/begin/length, UDP 트래커 action·transaction_id·interval·leechers·seeders·피어 목록·에러 메시지, DHT 메시지 종류·Transaction ID·Node ID·노드 목록
- 차이 ①: Wireshark 는 HTTP 트래커 응답을 일반 HTTP 로만 보여줍니다. 이 프로그램은 본문 bencode 까지 해석합니다(interval, complete, incomplete, peers).
- 차이 ②: 잘못된 connection_id 로 보낸 announce 요청을 Wireshark 는 "Connection Response" 로 잘못 해석했습니다. 이 프로그램은 announce 요청으로 맞게 해석했습니다.

---

## 5. 출력 예시 (일부, 전체는 docs/sample_output_lo.txt)

```
------------------------------------------------------------------------
#4 [22:30:10.097] [송신] BitTorrent Peer Wire - Handshake
 [IP ] 127.0.0.1 -> 127.0.0.1  TTL=64  ID=0xfca2  TotalLen=120  Proto=TCP(6)
 [TCP] 59788 -> 6881  Seq=4259413498  Ack=2257395806  Flags=[PSH,ACK]  Win=64  HdrLen=32  Len=68
 [TCP 연결 설정] 이 연결의 3-way handshake (앞서 캡처된 패킷)
       #1 [22:30:09.947] [송신] 59788 -> 6881  Flags=[SYN]  Seq=4259413497  (1단계 SYN: 연결 요청)
       #2 [22:30:09.947] [송신] 6881 -> 59788  Flags=[SYN,ACK]  Seq=2257395805  Ack=4259413498  (2단계 SYN+ACK: 연결 요청 수락)
       #3 [22:30:09.947] [송신] 59788 -> 6881  Flags=[ACK]  Seq=4259413498  Ack=2257395806  (3단계 ACK: 연결 확립)
 [APP] BitTorrent Handshake
       pstrlen    : 19
       pstr       : "BitTorrent protocol"
       Reserved   : 00 00 00 00 00 10 00 05  → [Extension Protocol(BEP 10)] [Fast Extension(BEP 6)] [DHT(BEP 5)]
       Info Hash  : 5a27bfa7070c7f62de1c67dead9ddb5b97b6acd1  (토렌트 식별값, info 딕셔너리의 SHA-1)
       Peer ID    : -qB4650-TEAM3CLIENT1
       Client     : qBittorrent (버전 코드 4.6.5.0)
------------------------------------------------------------------------
#14 [22:30:10.699] [송신] BitTorrent Peer Wire
 [IP ] 127.0.0.1 -> 127.0.0.1  TTL=64  ID=0x466d  TotalLen=1065  Proto=TCP(6)
 [TCP] 6881 -> 59788  Seq=2257396008  Ack=4259413588  Flags=[PSH,ACK]  Win=64  HdrLen=32  Len=1013
 [APP] BitTorrent Message: Piece (id=7, len=16393) - 요청한 블록 데이터 전송
       Index=0  Begin=0  블록 크기=16384 bytes (이 세그먼트에 1000 bytes)
       → 나머지 15384 bytes 는 다음 세그먼트로 이어짐
```

---

## 6. 분석 항목 정리 (보고서용)

| 계층 | 분석 필드 |
|---|---|
| 링크 | 송신/수신 방향(`sll_pkttype`), EtherType, VLAN 태그 |
| IPv4 | 출발지/목적지 IP, TTL, Identification, Total Length, Protocol, 조각화 여부 |
| TCP | 출발지/목적지 포트, Seq, Ack, Flags, Window, 헤더 길이, 데이터 길이 / **연결 설정(SYN → SYN+ACK → ACK), 데이터 전송, 연결 해제(FIN·ACK·RST)** |
| UDP | 출발지/목적지 포트, Length |
| Peer Wire 핸드셰이크 | pstrlen, pstr, Reserved 확장 비트(BEP 10/6/5), Info Hash, Peer ID → 클라이언트 추정 |
| Peer Wire 메시지 | 길이, ID, 이름·의미 / have·request·piece·cancel 의 index·begin·length / bitfield 보유 조각 수 / port / Extended Handshake(m, v, p, metadata_size, yourip) / keep-alive |
| HTTP 트래커 | announce·scrape 요청 파라미터(info_hash, peer_id, port, uploaded, downloaded, left, event, compact, numwant), 응답(interval, complete, incomplete, peers) |
| UDP 트래커 | action, connection_id, transaction_id, announce 필드, 응답의 interval·leechers·seeders·피어, scrape, error |
| DHT | y(질의/응답/오류), q(메서드), Transaction ID, Node ID, info_hash/target, token, port, nodes, values, 오류 코드, 질의-응답 매칭 |

## 7. 구현 포인트 (발표·보고서용)

1. **포트가 아니라 내용으로 판별합니다.** 요즘 클라이언트는 포트를 무작위로 쓰기 때문입니다.
   - 핸드셰이크: 첫 바이트 `19` + `"BitTorrent protocol"`
   - UDP 트래커: 고정값 `0x41727101980` + transaction_id 추적
   - DHT: bencode 딕셔너리의 `y`, `t` 키
2. **연결별 메시지 경계를 추적합니다.** Peer Wire 메시지(`[길이][ID][내용]`)는 TCP 세그먼트 경계와 맞지 않습니다. 그래서 연결(방향)마다 *다음 Seq*, *현재 메시지의 남은 길이*, *세그먼트에 걸친 헤더 조각* 을 기억합니다. 16KB piece 가 여러 세그먼트로 나뉘어도, 헤더가 두 세그먼트에 쪼개져도 해석합니다. 재전송은 Seq 로 걸러내고, 세그먼트를 놓치면 다음 메시지 시작을 다시 찾습니다.
3. **3-way handshake 를 소급해서 출력합니다.** SYN 시점에는 BitTorrent 인지 알 수 없습니다. 그래서 모든 SYN/SYN+ACK/ACK 를 기록해 두었다가, 핸드셰이크로 확인되는 순간 그 연결의 연결 설정 과정을 함께 출력합니다.
4. **예외 패킷을 처리합니다.** 모든 길이를 패킷 끝과 비교해서 짧거나 잘린 패킷은 건너뜁니다. 무작위·변형 패킷 70만 건을 AddressSanitizer 로 돌려 메모리 오류 0건을 확인했습니다.

## 8. 한계

- 암호화(MSE/PE) 연결은 탐지만 하고 내용은 해석할 수 없습니다.
- uTP(UDP 위의 BitTorrent 피어 연결)와 IPv6 는 분석하지 않습니다.
- TCP 를 완전히 재조립하지는 않습니다. 순서가 뒤바뀌거나 손실되면 다음 메시지부터 다시 추적합니다.
- HTTPS 트래커는 암호화되어 내용을 볼 수 없습니다.
