# BitTorrent 보고서 작성 팁

BitTorrent 파트를 보고서에 옮길 때 필요한 내용을 한곳에 모았습니다. 어느 캡처를 어디에 넣는지, 직접 실행해서 다시 캡처하는 방법, 검증 근거, 한계와 예상 질문을 정리했습니다. 분석기 자체의 설명(옵션, 구현 포인트)은 [README.md](README.md) 를 봅니다.

---

## 0. 제출할 파일 목록 (교수님 제출용)

과제 공지대로 설계보고서(PPT)와 함께 소스파일을 냅니다. BitTorrent 파트는 아래 필수 9개만 내면 됩니다. 이 9개만 넣은 빈 폴더에서 `make` 로 `bt_sniffer` 와 `test/bt_testgen` 이 경고 없이 빌드되는 것을 확인했습니다.

### 0-1. 필수 (9개)

| 파일 | 내용 |
| --- | --- |
| `main.c` | Raw Socket 캡처, 송수신 구분, Ethernet · IPv4 · TCP/UDP 헤더 분석, 공통 출력, 통계 |
| `common.h` | 패킷 정보 구조체 `struct pkt_info` 와 공통 출력 함수 선언 |
| `bittorrent.c`, `bittorrent.h` | BitTorrent 분석 (Peer Wire 핸드셰이크·메시지, HTTP/UDP 트래커, DHT) |
| `bencode.c`, `bencode.h` | bencode 파서 (DHT, 트래커 응답, 확장 핸드셰이크 해석에 사용) |
| `Makefile` | `make` 로 분석기와 테스트 생성기를 함께 빌드 |
| `test/bt_testgen.c` | 루프백 테스트 트래픽 생성기 (보고서의 루프백 결과를 재현할 때 필요) |
| `README.md` | 빌드·실행 방법, 옵션, 분석 항목, 한계 |

`Makefile` 이 `test/bt_testgen.c` 를 폴더 경로로 빌드하므로 `test/` 폴더 구조를 유지한 채 압축합니다.

```bash
# bit_torrent 폴더에서 (zip 이 없으면 sudo apt install zip)
zip -r bit_torrent_src.zip main.c common.h bittorrent.c bittorrent.h bencode.c bencode.h Makefile README.md test/bt_testgen.c
```

팀원 소스와 한 파일로 묶어 낼 때는 이 9개를 `bit_torrent/` 폴더째 넣습니다.

### 0-2. 선택 (결과 근거로 함께 내도 되는 것)

| 파일 | 내는 이유 |
| --- | --- |
| `captures/result_lo.txt`, `captures/result_real.txt` | 보고서 캡처 화면의 원본 텍스트 (내 공인 IP 는 가림) |
| `captures/bt_lo.pcap` | Wireshark 로 열어 바로 검증할 수 있는 루프백 패킷 원본 (약 25KB) |
| `scripts/verify_pcap.py` | pcap 을 따로 재조립해 분석기 통계를 검증한 스크립트 (5장 검증 결과의 근거) |
| `scripts/capture.sh` | 캡처 과정(4장)을 한 번에 재현하는 스크립트 |

### 0-3. 내지 않는 것

| 파일 | 이유 |
| --- | --- |
| `bt_sniffer`, `test/bt_testgen`, `*.o` | 빌드 결과물. 받는 쪽에서 `make` 로 만듭니다 |
| `captures/bt_real.pcap` | 약 43MB 이고 내 공인 IP 가 들어 있음 |
| `captures/png/`, `captures/전달용/` | 보고서 PPT 안에 들어가는 이미지 |
| `scripts/render_png.py`, `scripts/mask_ip.py` | 보고서 이미지 제작과 IP 가리기용 보조 도구 (분석 프로그램 자체와는 무관) |
| `report_tip.md` | 팀 내부용 보고서 작성 가이드 |
| `docs/`, `scripts/__pycache__/` | 삭제 예정인 예전 예시 파일, Python 캐시 |

## 1. 자료 위치

| 경로 | 내용 |
| --- | --- |
| `captures/전달용/` | 보고서에 넣을 PNG 9장: 분석기 출력 8장 + Wireshark 대조 화면 `wireshark_handshake.png` (아래 3장에서 위치 안내) |
| `captures/png/` | 보고서용 후보 PNG 전체 21장 (루프백 `lo_` 9장, 실제 토렌트 `real_` 12장) |
| `captures/result_lo.txt` | 루프백 테스트 분석 결과 (335줄) |
| `captures/result_real.txt` | 실제 토렌트 분석 결과 (7196줄, 내 공인 IP 는 가림) |
| `captures/bt_lo.pcap`, `captures/bt_real.pcap` | 같은 시간에 tcpdump 로 저장한 패킷 원본 (Wireshark 로 열기). `bt_real.pcap` 은 용량(약 43MB)과 공인 IP 때문에 레포에 올리지 않았고 캡처한 사람 PC 에만 있습니다 |
| `scripts/` | 캡처 자동 실행, 공인 IP 가리기, PNG 만들기, pcap 검증 스크립트 ([README.md](README.md) 4-5) |

PNG 읽는 법은 다음과 같습니다.

- 제목줄에 원본 파일, 줄 번호, 장면 설명이 있습니다. 왼쪽 숫자는 결과 txt 의 줄 번호입니다.
- 떨어진 구간을 한 장에 넣은 경우 사이에 "(중략)"이 있습니다.
- 결과 txt 의 해당 줄을 터미널 모양으로 그린 이미지이며, 내용은 txt 와 같습니다. 실제 터미널 화면 캡처가 필요하면 4장의 방법으로 다시 찍습니다. (`wireshark_handshake.png` 만 Wireshark 화면을 직접 찍은 것입니다.)
- 캡처한 사람의 공인 IP 는 PNG 와 `result_real.txt` 에서 `xxx.xxx.xxx.xxx` 로 가렸습니다(가리기 전후 줄 수가 같아 줄 번호 참조는 그대로입니다). 레포가 공개라 원본 `bt_real.pcap` 은 `.gitignore` 로 올리지 않습니다. 다른 피어들의 IP 는 같은 토렌트에 참여한 누구나 볼 수 있는 정보라 그대로 두었습니다.

한 패킷 블록은 다음 순서로 읽습니다.

```text
#번호 [시각] [송신/수신] 종류      ← 분석기가 받은 프레임 순번 (이번 캡처에서는 Wireshark 의 No. 와 같음, 아래 참고)
 [IP ] 출발지 -> 목적지  TTL  ID  TotalLen  Proto
 [TCP] 포트 -> 포트  Seq  Ack  Flags  Win  HdrLen  Len   (UDP 는 [UDP] 포트, Length)
 [APP] BitTorrent 계층 해석 결과
```

`#번호` 가 Wireshark 의 No. 와 같은 것은 이번 캡처에서 분석기와 tcpdump 가 같은 프레임을 빠짐없이 받았기 때문입니다(프레임 수 일치, 커널 드롭 0). 두 프로그램을 켜는 사이에 다른 패킷이 오갔거나 한쪽이 패킷을 놓치면 번호가 어긋나므로, 다시 캡처한 파일에서는 IP ID 나 Seq 로 같은 패킷인지 확인합니다.

## 2. 캡처 환경 (보고서 "실험 환경"에 그대로 사용)

| 항목 | 값 |
| --- | --- |
| 날짜 | 2026-11-25 |
| OS | Windows 11 Home + WSL2 Ubuntu 24.04.4 LTS (커널 6.6.87.2-microsoft-standard-WSL2) |
| 도구 | gcc 13.3.0, tcpdump 4.99.4, aria2 1.37.0 |
| 루프백 테스트 | `sudo ./bt_sniffer -i lo -d` + `./test/bt_testgen` (127.0.0.1) |
| 실제 토렌트 | `sudo ./bt_sniffer -i eth0 -p 6881` + aria2c, Debian 13.8.0 amd64 netinst 공식 토렌트, 2분 후 중지 |
| 토렌트 정보 | 파일 794,820,608 bytes, 256 KiB 조각 3,032개, Info Hash `e75a1a6b922815d64cfa9b8904208d3a85143495` |
| 트래커 | `bttracker.debian.org:6969` (평문 HTTP 트래커) |
| 원본 저장 | 같은 시간에 `tcpdump -i lo` / `tcpdump -i eth0` 로 pcap 저장 |

| 결과 | 루프백 | 실제 토렌트 |
| --- | --- | --- |
| 전체 프레임 (분석기 = tcpdump) | 79 = 79 | 15,770 = 15,770 (송신 7,766 / 수신 8,004) |
| 커널 드롭 (tcpdump 종료 메시지 기준) | 0 | 0 |
| BitTorrent 로 출력한 패킷 | 38 | 699 |
| 받은 데이터 | - | 41,009,152 bytes (종료 시 트래커에 보낸 downloaded 값) |

## 3. 보고서 구성과 캡처 배치

아래는 BitTorrent 동작 순서대로 쓰는 목차 예시입니다. 과제 공지의 목차가 따로 있으면 그 순서에 맞춰 옮깁니다.

### 3-1. 보고서에서 보여 줄 항목과 근거

| 보여 줄 항목 | 근거 이미지 |
| --- | --- |
| Raw Socket 으로 송신·수신을 모두 캡처 | real_12 (송신 7,766 / 수신 8,004), 모든 이미지의 [송신]/[수신] |
| IP · TCP/UDP 헤더 분석 | 모든 이미지의 [IP], [TCP]/[UDP] 줄 |
| TCP 연결 설정 (3-way handshake) | real_02 |
| TCP 데이터 전송과 세그먼트 경계 | real_05 |
| TCP 연결 해제 (FIN · ACK · RST) | real_06 |
| 응용 계층 해석 (트래커, Peer Wire, DHT) | real_01, real_03, real_09, lo_07 |
| 결과 검증 | wireshark_handshake, real_12 + 5장의 Wireshark 대조 |

### 3-2. 목차별 배치 (전달용 9장)

| 목차 | 이미지 | 원본 줄 | Wireshark 프레임 |
| --- | --- | --- | --- |
| 결과 1. 트래커로 피어 찾기 | real_01_http_tracker_started | result_real 3-27 | 51, 57 |
| 결과 2. TCP 연결 설정 + 핸드셰이크 | real_02_handshake | result_real 29-42 | 63, 84, 86, 167 |
| 결과 2. (이어서) 상대 응답 | real_03_handshake_reply | result_real 67-99 | 183, 184 |
| 결과 3. 데이터 전송 (piece) | real_05_piece | result_real 623-628, 658-672 | 638, 693, 697 |
| 결과 4. 연결 해제 | real_06_fin_peer | result_real 2027-2035, 2053-2056 | 2260, 2261, 2307 |
| 결과 5. DHT | real_09_dht_ping | result_real 59-65, 166-173 | 178, 204 |
| 결과 6. UDP 트래커 | lo_07_udp_tracker | result_lo 150-216 | bt_lo.pcap 52~59 |
| 결과 7. 캡처 통계 | real_12_stats | result_real 7173-7196 | 전체 15,770 |
| 검증. Wireshark 대조 | wireshark_handshake | (real_02 와 같은 패킷) | 167 |

png/ 폴더에서 더 넣을 만한 이미지는 다음과 같습니다.

- real_04_interested_request: 핸드셰이크(결과 2)와 piece(결과 3) 사이의 interested → unchoke → request 흐름입니다. 결과 2와 3 사이에 넣으면 흐름이 끊기지 않습니다.
- real_10_dht_find_node: find_node 질의와 응답(Transaction ID 5fe76c6b 일치)입니다. 응답의 nodes 에 다른 노드 8개가 들어 있어 DHT 가 노드를 따라가며 찾는 방식을 보여 줍니다. real_09 대신 또는 함께 넣습니다.
- lo_05_fin: 교과서대로의 4-way 해제(FIN → ACK → FIN → ACK)입니다. real_06 은 RST 로 끝나므로 비교용으로 좋습니다.
- real_07_fin_shutdown: 내 쪽이 먼저 끊는 해제(FIN → ACK → RST)입니다.

### 3-3. 이미지별로 본문에 쓸 내용

#### real_01 · 트래커로 피어 찾기

- aria2 가 Debian 공식 트래커에 시작을 알리는 announce 요청입니다(event=started). peer_id `A2-1-37-0-` 는 aria2 1.37.0, left=794,820,608 은 받아야 할 전체 크기, supportcrypto=1 은 암호화 지원 알림입니다.
- 응답 본문은 bencode 딕셔너리입니다. interval 900초(다음 announce 까지 대기), 피어 19개(compact: IP 4 + 포트 2 = 6바이트씩)가 들어 있습니다.
- 실제로는 이 요청 전 약 1분 동안 트래커가 SYN 에 응답하지 않아 SYN 재전송(처음 5번은 1초 간격, 그 뒤 2 → 4 → 8 → 16초 간격)만 있었습니다. 연결이 맺어지지 않아 분석기 출력에는 없고 bt_real.pcap 앞부분에서 볼 수 있습니다.

#### real_02 · TCP 연결 설정 + 핸드셰이크

- 내 PC(172.23.1.248, WSL 내부 사설 IP)가 트래커가 준 피어 67.230.146.141:59501 에 연결합니다.
- SYN(Seq=2334915552) → SYN+ACK(Ack=2334915553 = 상대 Seq+1) → ACK. SYN 에서 SYN+ACK 까지 약 251ms 가 이 피어와의 왕복 지연(RTT)입니다.
- SYN 만으로는 BitTorrent 인지 알 수 없어서, 분석기는 핸드셰이크를 확인한 순간 기록해 둔 3-way handshake 를 함께 출력합니다(README 7장 3번).
- 핸드셰이크 68바이트 = pstrlen 1 + "BitTorrent protocol" 19 + Reserved 8 + Info Hash 20 + Peer ID 20. Info Hash 는 트래커 요청의 info_hash 와 같습니다.
- 짚을 점: 3-way 직후 Seq 는 2334915553 인데 핸드셰이크는 2334916212 에서 시작합니다. 핸드셰이크 앞에 659바이트가 먼저 오갔고, 바이트 수 구조로 보아 MSE 암호화 협상 끝에 평문 모드로 정한 것으로 보입니다(tcpdump 에서도 `seq 660:728`). 포트가 아니라 내용으로 판별하기 때문에 스트림 중간의 핸드셰이크도 찾아냈습니다(README 7장 1번).

#### real_03 · 상대 응답

- 상대 Peer ID `-lt0D80-` 은 libTorrent(rakshasa) 0.13.8 입니다. Reserved 끝 바이트가 01 이라 DHT 와 확장 메시지만 지원하고 Fast Extension 은 지원하지 않습니다.
- 세그먼트 하나에 핸드셰이크, 확장 핸드셰이크(BEP 10), Bitfield 가 이어서 들어 있습니다. 분석기는 세그먼트 안을 메시지 단위로 나눠 해석합니다.
- Bitfield 379바이트 = 3,032비트이고, 794,820,608 ÷ 3,032 = 262,144 이므로 조각 하나가 256 KiB 입니다.
- 내 쪽(#184)은 aria2 의 확장 핸드셰이크와 Port(DHT 6881)입니다. 확장 번호(ut_metadata=9)는 각자 정하므로 상대(2)와 다릅니다.

#### real_05 · 데이터 전송 (piece)

- Piece 메시지 = `[길이 4][ID 7][Index 4][Begin 4][데이터 16,384]`. #638 은 Len=13 으로 헤더만 있고 데이터는 0바이트입니다.
- #693 은 앞 2,876바이트가 이전 블록(Begin=0)의 끝이고, 그 뒤에서 다음 블록(Begin=16384)이 시작합니다. BitTorrent 메시지 경계와 TCP 세그먼트 경계가 다르다는 것, 분석기가 연결마다 경계를 추적한다는 것(README 7장 2번)을 보여 줍니다.
- Seq 로 검산할 수 있습니다. #638 끝(3767183545)과 #693 시작(3767197053) 사이 13,508바이트가 출력이 생략된 이어진 세그먼트이고(-v 로 보임), 16,384 − 13,508 = 2,876 과 맞습니다.
- 세그먼트 길이(7,368, 11,052)가 MTU 1500 보다 큰 것은 수신 측에서 여러 패킷을 합쳐 올리는 기능(GRO 등) 때문입니다.

#### real_06 · 연결 해제

- 피어 75.164.191.25 가 먼저 FIN 을 보내고, 내 쪽은 ACK 와 FIN 을 한 패킷(FIN+ACK, Ack = 상대 FIN Seq+1)으로 보내 4단계가 3단계로 줄었습니다. FIN 은 데이터 길이가 0 이어도 순서 번호 하나를 씁니다.
- 상대 FIN 의 Ack=991146984 는 내 핸드셰이크(68바이트)를 아직 확인하지 않은 값이고, 상대는 데이터도 보내지 않았습니다. 상대 프로그램이 연결을 받자마자 닫았고, 그 뒤 도착한 내 데이터에 상대 커널이 RST 로 답한 것으로 보입니다.
- 교과서의 4-way 해제와 비교하려면 lo_05_fin 을 함께 넣습니다.

#### real_09 · DHT

- DHT(BEP 5)는 UDP 위의 bencode 메시지입니다. y 는 q(질의)/r(응답)/e(오류)이고, Transaction ID 로 질의와 응답의 짝을 맞춥니다.
- 내 노드가 보낸 ping(TID 035a3bc2)에 약 0.2초 뒤 같은 TID 의 응답이 왔습니다. v 는 클라이언트 표시입니다(A2 = aria2, LT = libtorrent).
- 응답의 ip 필드는 상대가 본 내 공인 주소입니다. 포트가 6881 이 아니라 62995 인 것은 NAT(WSL, 공유기)가 포트를 바꿨기 때문입니다.

#### lo_07 · UDP 트래커 (BEP 15)

- Debian 토렌트에는 HTTP 트래커만 있어서 실제 캡처에는 UDP 트래커가 없습니다. 그래서 루프백 테스트로 보완했다고 씁니다.
- connect(고정값 0x41727101980) → Connection ID 발급 → announce(interval, 리처 3, 시더 5, 피어 3개) → scrape → 잘못된 Connection ID 로 보낸 announce 에 error 응답 순서입니다.
- UDP 에는 연결이 없으므로 Connection ID 로 위조된 요청을 막고, Transaction ID 로 요청과 응답의 짝을 맞춥니다.

#### real_12 · 캡처 통계

- 전체 15,770프레임이 tcpdump 와 같고 커널 드롭은 0 입니다. 송신 7,766 / 수신 8,004 로 양방향을 모두 잡았습니다.
- Have 740 이 많은 것은 조각 하나를 완성할 때마다 연결된 피어 모두에게 알리기 때문입니다. Allowed Fast 와 Have All 은 Fast Extension(BEP 6) 메시지입니다.
- 연결 설정 6 은 3-way 가 함께 출력된 연결 수, 해제 21 은 FIN 7개 + RST 14개입니다(FIN 에 대한 ACK 4개는 출력만 하고 이 숫자에는 넣지 않음). 재전송 96 은 같은 Seq 로 다시 온 세그먼트를 걸러 낸 수입니다.
- UDP 트래커 0 은 위 lo_07 설명과 같은 이유입니다.

#### wireshark_handshake · 검증

- real_02 의 핸드셰이크(#167)를 Wireshark 에서 표시 필터 `tcp.seq_raw == 2334916212` 로 찾은 화면입니다. TCP 설정에서 Relative sequence numbers 를 꺼서 TCP 요약 줄에 실제 Seq 가 바로 보입니다.
- 분석기 출력과 일치하는 값: No. 167, 172.23.1.248 → 67.230.146.141, 포트 56606 → 59501, Seq 2334916212, Ack 3767182953, Len 68, Reserved `0000000000100005`, Info Hash `e75a1a6b922815d64cfa9b8904208d3a85143495`, 상태 표시줄의 전체 패킷 15,770.
- Peer ID 는 Wireshark 가 16진수(`41322d31…`), 분석기가 글자(`A2-1-…`)로 보여 줄 뿐 같은 바이트입니다(0x41='A', 0x32='2', 0x2d='-').
- Wireshark 의 Length 134 는 Ethernet 헤더 14바이트를 포함한 프레임 길이이고, 분석기의 TotalLen 120 은 IP 패킷 길이입니다(134 = 14 + 120).
- 슬라이드에서는 real_02 와 나란히 놓고 Seq, Info Hash, Reserved 에 같은 색 표시를 하면 검증 한 장이 됩니다.

## 4. 직접 실행·캡처하는 방법 (WSL2 Ubuntu)

빌드(4-1)만 하면 4-2·4-3 을 스크립트 한 줄로 할 수 있습니다. 결과는 새 폴더 `captures/run_<날짜_시각>/` 에 저장되어 레포의 기존 결과를 덮어쓰지 않고, `result_real.txt` 의 내 공인 IP 도 자동으로 가립니다.

```bash
sudo bash scripts/capture.sh lo      # 루프백 테스트 (약 15초)
sudo bash scripts/capture.sh real    # 실제 토렌트 (토렌트 파일이 없으면 Debian 공식 사이트에서 받음, 약 2분 30초)
sudo bash scripts/capture.sh all     # 둘 다
```

스크립트가 하는 일은 아래 4-2·4-3 의 수동 절차와 같습니다. 각 단계를 눈으로 보면서 하거나 터미널 화면을 직접 찍으려면 수동 절차를 따릅니다.

### 4-1. 준비와 빌드

```bash
sudo apt install -y build-essential tcpdump aria2
cd <레포 경로>/bit_torrent        # 예: cd "/mnt/c/학교 작업 코드/NetworkProject/bit_torrent"
make                              # → ./bt_sniffer, ./test/bt_testgen
mkdir -p captures
```

이미 있는 결과 파일은 덮어쓰므로, 새로 찍기 전에 `captures/` 를 다른 이름으로 복사해 둡니다.

### 4-2. 루프백 테스트

터미널 세 개를 열고 모두 `bit_torrent` 폴더에서 실행합니다.

```bash
# 터미널 1 - 패킷 원본 저장
sudo tcpdump -i lo -w captures/bt_lo.pcap

# 터미널 2 - 분석기
sudo ./bt_sniffer -i lo -d | tee -i captures/result_lo.txt

# 터미널 3 - 테스트 트래픽 (약 8초, "완료"가 나오면 끝)
./test/bt_testgen
```

끝낼 때는 터미널 2 에서 `Ctrl+C` 를 눌러 통계가 출력된 것을 확인하고, 그다음 터미널 1 에서 `Ctrl+C` 를 누릅니다.

- `tee -i` 를 쓰는 이유: `Ctrl+C` 는 파이프라인의 모든 프로그램에 SIGINT 를 보냅니다. `-i` 가 없으면 tee 가 먼저 종료되어, 분석기가 종료 직전에 출력하는 통계가 파일에 저장되지 않습니다.
- tcpdump 가 파일을 만들지 못한다는 권한 오류가 나면 `-Z root` 를 붙입니다.

### 4-3. 실제 토렌트

토렌트는 레포 밖의 폴더에서 받습니다. aria2 가 ISO 크기(약 758MB)만큼 디스크 공간을 미리 잡기 때문입니다.

```bash
mkdir -p ~/bt_download && cd ~/bt_download
# https://cdimage.debian.org/debian-cd/current/amd64/bt-cd/ 에서 netinst 토렌트 이름 확인 후 받기
curl -LO https://cdimage.debian.org/debian-cd/current/amd64/bt-cd/debian-13.8.0-amd64-netinst.iso.torrent
```

`current` 의 버전이 바뀌면 파일 이름도 바뀌므로 페이지에서 이름을 확인합니다. 그다음 터미널 세 개에서 실행합니다.

```bash
# 터미널 1 (bit_torrent 폴더) - 패킷 원본 저장
sudo tcpdump -i eth0 -w captures/bt_real.pcap

# 터미널 2 (bit_torrent 폴더) - 분석기를 토렌트보다 먼저 켭니다 (핸드셰이크는 연결 시작 순간에만 옴)
sudo ./bt_sniffer -i eth0 -p 6881 | tee -i captures/result_real.txt

# 터미널 3 (~/bt_download 폴더) - 토렌트 시작
aria2c --listen-port=6881 --dht-listen-port=6881 --disable-ipv6=true \
       --bt-require-crypto=false --seed-time=0 debian-*-amd64-netinst.iso.torrent
```

끝내는 순서는 다음과 같습니다.

1. 1~2분 뒤 터미널 3 에서 `Ctrl+C` 를 누릅니다. aria2 가 트래커에 stopped 를 알리고 연결을 닫을 때까지 몇 초 기다립니다(FIN 캡처).
2. 터미널 2 에서 `Ctrl+C` 를 누르고 통계를 확인합니다.
3. 터미널 1 에서 `Ctrl+C` 를 누릅니다.
4. `~/bt_download` 의 `.iso` 와 `.iso.aria2` 를 지웁니다. 남아 있으면 다음 캡처 때 이미 받은 조각을 다시 받지 않아 트래픽이 달라집니다. `.torrent` 는 남겨 둡니다.

주의할 점은 다음과 같습니다.

- 이번 캡처에서는 트래커가 처음 약 1분 동안 응답하지 않았습니다. 화면에 아무것도 안 나와도 2분 정도 기다립니다.
- WSL `eth0` 에는 WSL 안의 모든 트래픽이 잡히므로, 캡처하는 동안 apt 같은 다른 네트워크 작업은 하지 않습니다.
- 학교·기숙사망은 P2P 를 막을 수 있습니다. 트래커 요청만 보이고 피어 연결이 없으면 휴대폰 핫스팟 등 다른 네트워크에서 다시 합니다.
- 실행할 때마다 피어, 포트, Seq 가 달라지므로 이 문서의 줄 번호와 프레임 번호는 이번 캡처 파일에만 해당합니다.
- `bt_real.pcap` 은 `.gitignore` 에 있어 커밋되지 않습니다(`captures/run_*/` 안의 것도 포함). 수동으로 새로 찍은 `result_real.txt` 를 올릴 때는 `python3 scripts/mask_ip.py captures/result_real.txt` 로 `ip (상대가 본 내 주소)` 줄의 내 공인 IP 를 가린 뒤 올립니다(줄 수는 그대로).

### 4-4. 보고서용 화면 만들기

- `captures/png/` 와 같은 모양의 이미지는 `scripts/render_png.py` 로 만듭니다. Windows 의 Python 에서 `pip install pillow` 후 실행합니다.

  ```bash
  python scripts/render_png.py captures/result_real.txt 29-42 -t "3-way handshake + 핸드셰이크" -o real_02.png
  python scripts/render_png.py captures/result_real.txt 251-254 566-585 -t "interested → unchoke → request" -o real_04.png
  python scripts/render_png.py --preset 20261125      # captures/png/ 21장을 그대로 다시 만듦
  ```

- 터미널 화면을 직접 찍을 때는 해당 부분이 보이게 스크롤한 뒤 Windows 의 `Win+Shift+S` 로 영역을 캡처합니다. 긴 구간은 `sed -n '29,42p' captures/result_real.txt` 처럼 필요한 줄만 출력해서 찍으면 깔끔합니다.
- 결과 txt 에서 장면을 찾을 때 쓰는 검색어입니다.

| 장면 | 검색 명령 |
| --- | --- |
| 핸드셰이크 + 3-way | `grep -n "Handshake" captures/result_real.txt` |
| piece | `grep -n "Piece (id=7" captures/result_real.txt` |
| 연결 해제 | `grep -n "연결 해제" captures/result_real.txt` |
| 트래커 | `grep -n "Tracker" captures/result_real.txt` |
| DHT | `grep -n "DHT -" captures/result_real.txt` |
| 통계 | `grep -n "캡처 통계" captures/result_real.txt` |

## 5. Wireshark 로 대조하는 방법 (보고서 "검증")

1. Windows 에서 Wireshark 로 `captures/bt_real.pcap` (또는 `bt_lo.pcap`)을 엽니다. `bt_real.pcap` 은 레포에 없으므로 캡처한 사람 PC 에서 하거나 4-3 으로 다시 캡처합니다. 레포만 받은 경우에는 `bt_lo.pcap` 으로 확인합니다.
2. 편집 → 설정 → Protocols → TCP → Relative sequence numbers 를 끕니다. 분석기는 Seq/Ack 실제 값을 출력합니다.
3. 이번 캡처에서는 분석기의 `#번호` 가 Wireshark 의 No. 와 같습니다(1장 참고). 표시 필터에 `frame.number in {63, 84, 86, 167}` 처럼 3-2 표의 프레임 번호를 넣으면 같은 패킷만 남습니다. 특정 패킷 하나는 `tcp.seq_raw == 2334916212` 처럼 실제 Seq 로도 찾을 수 있습니다.
4. 같은 패킷에서 IP ID, TTL, Seq, Ack, Flags, Len 을 비교합니다. 분석기는 IP ID 를 16진수로 출력합니다(예: 0xdab7 = 55991).

알아 둘 점은 다음과 같습니다.

- 실제 캡처의 피어 포트(59501 등)는 BitTorrent 기본 포트(6881~6889)가 아니고 핸드셰이크 앞에 협상 바이트가 있지만, #167·#183 은 Wireshark 가 내용을 보고 BitTorrent 로 해석했습니다(`wireshark_handshake.png`). 해석되지 않는 연결이 있으면 패킷 우클릭 → Decode As 로 지정하거나, 아래 Packet Bytes 창에서 `.BitTorrent protocol` 문자열과 Info Hash 바이트로 대조합니다.
- 루프백(bt_lo.pcap)은 6881 포트라 Wireshark 가 바로 BitTorrent 로 해석합니다. 디스플레이 필터는 `bittorrent || bt-dht || bt-tracker` 입니다. 트래커가 HTTP 로, DHT 가 BT-DHT 로 표시되지 않으면 패킷 우클릭 → Decode As 로 지정합니다.
- 체크섬은 기본 설정에서 `[unverified]` 로 표시됩니다. 체크섬 검증을 켜면 송신 패킷이 "incorrect" 로 나올 수 있는데, 체크섬 계산을 네트워크 장치에 맡기는 offload 때문이며 오류가 아닙니다.

이미 확인한 검증 결과입니다(보고서에 근거로 씁니다).

- 프레임 수: 루프백 79 = tcpdump 79, 실제 15,770 = tcpdump 15,770, 커널 드롭 0.
- 프레임 번호: 분석기 #4, #38(루프백), #51, #63, #167, #183, #2260, #15651(실제)의 IP ID 가 pcap 의 같은 번호 프레임과 모두 일치했습니다.
- 필드 값: #167 을 Wireshark 화면에서 직접 대조해 IP, 포트, Seq, Ack, Len, Reserved, Info Hash, Peer ID 가 모두 같았습니다(`wireshark_handshake.png`).
- 메시지 수: bt_real.pcap 의 TCP 스트림을 `scripts/verify_pcap.py` 로 따로 재조립해 직접 센 값과 분석기 통계가 Have 740, Request 480, Extended 18, Port 10, Unchoke 6, Interested 5, Bitfield 5, Allowed Fast 25, Have All 2, Keep-Alive 1 로 모두 같았습니다. Piece 만 다릅니다(7장 한계 2번).
- 루프백 tshark 대조 결과(Seq/Ack, Info Hash, 메시지 순서, UDP 트래커, DHT 필드 일치와 Wireshark 와의 차이 2가지)는 [README.md](README.md) 4-4 장에 있습니다.

## 6. 보고서 본문에 쓸 개념 정리

BitTorrent 동작 순서입니다.

1. `.torrent` 파일에서 info 딕셔너리의 SHA-1 인 Info Hash(토렌트 식별값)를 얻습니다.
2. 트래커(HTTP/UDP)나 DHT 에 Info Hash 를 보내 같은 파일을 가진 피어 목록을 받습니다.
3. 피어와 TCP 연결을 맺고 핸드셰이크(68바이트)로 같은 토렌트인지 확인합니다.
4. Bitfield / Have 로 서로 가진 조각을 알리고, 확장 핸드셰이크로 지원 기능을 교환합니다.
5. Interested → Unchoke 뒤에 Request 로 16 KiB 블록을 요청하고 Piece 로 받습니다.
6. 조각을 다 받으면 SHA-1 로 확인하고 Have 로 알립니다. 종료할 때 트래커에 stopped 를 알리고 연결을 닫습니다.

Peer Wire 메시지 형식은 `[길이 4바이트][ID 1바이트][내용]` 이고, 길이 0 은 Keep-Alive 입니다.

구현 포인트 4가지(README 7장)를 실제 캡처에서 확인한 사례와 연결해 씁니다.

| 구현 포인트 | 실제 캡처에서 확인한 사례 |
| --- | --- |
| 포트가 아니라 내용으로 판별 | real_02: 비표준 포트(59501)이고 스트림 중간(협상 바이트 659 뒤)에서 시작한 핸드셰이크도 찾음 |
| 연결별 메시지 경계 추적 | real_05: 세그먼트 경계와 다른 piece 블록 경계를 Seq 로 검산 |
| 3-way handshake 소급 출력 | real_02: SYN 시점에는 알 수 없던 연결을 핸드셰이크 확인 후 함께 출력 |
| 예외 패킷 처리 | 길이 검사, 무작위·변형 패킷 70만 건 AddressSanitizer 테스트(README 7장 4번) |

## 7. 한계와 고찰

1. 처음부터 암호화된 연결은 보이지 않습니다. `scripts/verify_pcap.py` 로 상대별 수신량을 나눠 보면, 이번에 받은 TCP 데이터 약 41.4MB 중 약 34.5MB(약 83%)가 평문 핸드셰이크가 없는 연결이었고(한 피어에서만 23.6MB), 평문 핸드셰이크가 있는 연결은 약 6.9MB(약 17%)였습니다. 평문 핸드셰이크가 없는 쪽에는 트래커·HTTPS 연결도 섞여 있지만 수 KB 수준이라, 거의 전부가 처음부터 암호화된 피어 연결입니다. 분석기는 평문 핸드셰이크로 BitTorrent 를 판별하므로, 처음부터 암호화된 연결은 BT 포트(6881~6889, `-p` 로 지정한 포트)일 때만 "평문 핸드셰이크 아님"으로 표시됩니다. 이번에는 양쪽 포트가 모두 무작위라 통계의 "평문 아닌 BT 포트 연결"도 0 이었습니다. 개선 방향: 트래커·DHT 응답에서 얻은 피어 IP:포트 목록과 연결 상대를 대조하면 암호화된 연결도 BitTorrent 로 분류할 수 있습니다.
2. TCP 를 완전히 재조립하지 않습니다. 통계의 Piece 는 361 인데 pcap 을 재조립해 직접 세면 최소 414 입니다. 세그먼트가 빠진 뒤 다음 메시지 시작을 다시 찾는 동안 일부 piece 를 놓쳤습니다(경계 재탐색 4).
3. UDP 트래커는 실제 캡처에 없습니다(Debian 토렌트는 HTTP 트래커만 사용). 루프백 테스트로 보완했습니다.
4. WSL2 NAT 환경이라 외부 피어가 먼저 접속해 올 수 없습니다. 모든 피어 연결은 내 쪽에서 걸었고, 2분 동안 업로드는 0 이었습니다. DHT 응답의 내 주소 포트(62995)가 6881 과 다른 것도 NAT 때문입니다.
5. uTP(UDP 위의 피어 연결)와 IPv6 는 분석하지 않습니다(aria2 에 `--disable-ipv6=true` 사용).

## 8. 발표 예상 질문

Q. 핸드셰이크의 Seq 가 3-way 직후 값보다 659 큰 이유는 무엇인가요?
A. 핸드셰이크 앞에 659바이트가 먼저 오갔기 때문입니다. 바이트 수 구조가 MSE 암호화 협상(DH 공개키 96바이트, 해시 40바이트, 협상 필드와 패딩)과 맞고, 협상 끝에 평문 모드를 골라 평문 핸드셰이크가 이어진 것으로 보입니다. pcap 에서 내 쪽은 #102(520바이트)와 #127(139바이트)로 합계 659바이트, 상대는 #125(149바이트)와 #166(14바이트)로 합계 163바이트를 보냈습니다. 상대의 마지막 14바이트는 MSE 의 VC 8 + crypto_select 4 + 패딩 길이 2 와 크기가 같습니다. 분석기는 포트나 스트림 시작 위치가 아니라 내용으로 판별해서 이 핸드셰이크를 찾았습니다.

Q. Wireshark 에서는 같은 패킷의 Seq 가 660, Length 가 134 로 보이는데 분석기와 다른가요?
A. 같은 값을 다르게 표시한 것입니다. Seq 660 은 Wireshark 가 연결 시작을 0 으로 잡은 상대 번호이고, 실제 값(Sequence Number (raw))은 2334916212 로 같습니다. Length 134 는 Ethernet 헤더 14바이트를 포함한 프레임 길이이고, 분석기의 TotalLen 120 은 IP 패킷 길이입니다.

Q. 세그먼트 길이가 MTU(1500)보다 큰 이유는 무엇인가요?
A. 수신 측에서 여러 세그먼트를 하나로 합쳐 올려 주는 기능(GRO 등) 때문입니다. 캡처는 합쳐진 뒤의 패킷을 보므로 Wireshark 에서도 똑같이 보입니다.

Q. FIN 뒤에 RST 가 나오는 이유는 무엇인가요?
A. 프로그램이 소켓을 닫은 뒤에 상대의 데이터가 도착하면 커널이 RST 로 답합니다. real_07 의 연결에서는 aria2c 가 FIN(#15651)을 보낸 뒤 상대가 재전송한 데이터 1,228바이트(#15690)가 도착해 내 커널이 RST(#15691)로 답했고, 이어서 온 상대의 ACK(#15715)에도 RST(#15716)로 답했습니다. #15690 은 재전송이라 분석기 출력에는 없고 bt_real.pcap 에서 볼 수 있습니다.

Q. Have 메시지가 740개나 되는 이유는 무엇인가요?
A. 조각 하나를 완성할 때마다 연결된 피어 모두에게 Have 를 보내기 때문입니다.

Q. 우리가 받는 토렌트가 아닌 get_peers 질의가 오는 이유는 무엇인가요? (real_11)
A. DHT 는 Info Hash 와 Node ID 의 XOR 거리가 가까운 노드에게 묻습니다. 그 질의의 Info Hash(89050f…)가 내 Node ID(890515…)와 앞자리가 같아 가까웠기 때문입니다. DHT 에 참여하면 다른 토렌트 검색도 돕게 됩니다.

Q. 분석 결과가 맞는지 어떻게 확인했나요?
A. 같은 시간에 tcpdump 로 저장한 pcap 과 프레임 수(15,770)가 같고, 분석기의 번호와 pcap 프레임 번호의 IP ID 가 일치합니다. 핸드셰이크 패킷(#167)은 Wireshark 화면에서 Seq, Info Hash 등 필드 값까지 같은 것을 확인했습니다. pcap 을 따로 재조립해 센 메시지 수도 Piece 를 빼고 모두 같았습니다. 루프백 테스트는 tshark 와 필드 단위로 대조했습니다.

Q. 3-way handshake 가 BitTorrent 연결이라는 것을 SYN 단계에서 어떻게 알았나요?
A. SYN 단계에서는 알 수 없습니다. 모든 SYN · SYN+ACK · ACK 를 기록해 두었다가, 그 연결에서 핸드셰이크가 확인되는 순간 연결 설정 과정을 함께 출력합니다.
