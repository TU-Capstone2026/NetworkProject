# NetworkProject

컴퓨터네트워크 설계 3팀 · Raw Socket 패킷 분석기

팀원이 프로토콜을 하나씩 맡아, 리눅스 Raw Socket(`AF_PACKET` / `SOCK_RAW`)으로 송신·수신 패킷을 직접 캡처하고 헤더와 응용 계층을 해석하는 프로그램을 만들었습니다. 결과는 파트별로 Wireshark·tcpdump와 표준 도구(curl, dig, traceroute 등)의 출력, 또는 캡처 GUI 로 확인했습니다(2장 표의 "결과 확인·검증").

---

## 1. 파트별 구성

| 폴더 | 프로토콜 | 담당 (GitHub) | 실행 파일 | 자세한 설명 |
| --- | --- | --- | --- | --- |
| [HTTP_Code/http_sniffer](HTTP_Code/http_sniffer/) | HTTP/1.0 · 1.1 · 2 (HPACK) | healer-tanker | `http_sniffer` | [README.md](HTTP_Code/http_sniffer/README.md), [README2.md](HTTP_Code/http_sniffer/README2.md) (테스트 명령 설명) |
| [HTTP_Test_Result](HTTP_Test_Result/) | HTTP 테스트 결과 | healer-tanker | - | [README.md](HTTP_Test_Result/README.md) (1·2차 테스트, Wireshark 패킷별 대조) |
| [Minho_DNS_Traceroute](Minho_DNS_Traceroute/) | DNS · ICMP(Traceroute) | MINHO2022 | `dns_capture`, `trace_capture` | [README.md](Minho_DNS_Traceroute/README.md) (용어 설명, 발표 예상 질문 포함) |
| [Email-Protocol](Email-Protocol/) | SMTP · POP3 · IMAP | Cyclaret | `mail_capture`, `mail_server` + Python GUI·송수신기 | [README.md](Email-Protocol/README.md) |
| [bit_torrent](bit_torrent/) | BitTorrent (Peer Wire · 트래커 · DHT) | Rael0515 | `bt_sniffer`, `test/bt_testgen` + 캡처·검증 스크립트 `scripts/` | [README.md](bit_torrent/README.md), [report_tip.md](bit_torrent/report_tip.md) (보고서 작성 팁) |

## 2. 파트별 비교

| | HTTP | DNS · Traceroute | 이메일 | BitTorrent |
| --- | --- | --- | --- | --- |
| 언어 | C | C | C (캡처·서버) + Python (송수신·GUI) | C |
| 전송 계층 | TCP | UDP / ICMP | TCP (외부 실습은 TLS) | TCP · UDP |
| 실행 환경 | WSL2 Ubuntu | WSL2 Ubuntu | Linux 또는 macOS (macOS 는 libpcap 사용) | WSL2 Ubuntu |
| 캡처 인터페이스 | `eth0` | `eth0` | 로컬 `lo`(macOS `lo0`), 외부는 실제 인터페이스 | 테스트 `lo`, 실제 토렌트 `eth0` |
| 트래픽 발생 | curl | dig, traceroute | `sender.py` / `receiver.py` (로컬 서버, Gmail) | `test/bt_testgen`, aria2c |
| 결과 확인·검증 | Wireshark pcapng 와 패킷별 대조 | dig·traceroute 출력, Wireshark | 캡처 GUI, Wireshark (IMAP·POP3) | tcpdump pcap·Wireshark 와 개수·필드 대조, pcap 재조립 검증 |

공통 구현 방식은 다음과 같습니다.

- `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` 로 링크 계층 프레임을 받고, `recvfrom()` 이 돌려주는 `sll_pkttype` 이 `PACKET_OUTGOING` 이면 송신으로 구분합니다.
- Ethernet → IPv4 → TCP/UDP(ICMP) → 응용 계층 순서로 헤더를 직접 해석합니다.
- TCP 를 쓰는 파트(HTTP, 이메일, BitTorrent)는 연결 설정(SYN → SYN+ACK → ACK)과 해제(FIN·ACK·RST)를 함께 보여 줍니다.
- Raw Socket 은 root 권한이 필요하므로 캡처 프로그램은 `sudo` 로 실행합니다.

## 3. 빠른 시작 (WSL2 Ubuntu 기준)

공통 준비입니다.

```bash
sudo apt install -y build-essential     # gcc, make
sudo apt install -y tcpdump             # 캡처 원본(pcap) 저장이 필요할 때
```

모든 파트가 같은 순서로 동작합니다. 터미널 1 에서 캡처 프로그램을 먼저 켜고, 터미널 2 에서 트래픽을 발생시킨 뒤, 터미널 1 에서 `Ctrl+C` 로 끝냅니다. 자세한 옵션과 결과 해석은 각 폴더의 README 를 봅니다.

### HTTP

```bash
cp -r HTTP_Code/http_sniffer ~/http_sniffer && cd ~/http_sniffer   # /mnt/c 실행 권한 문제를 피하려고 WSL 홈에서 실행
make
sudo ./http_sniffer eth0 -v | tee sniff_wsl.log     # 터미널 1
curl --http1.1 http://httpbin.org/get              # 터미널 2
```

### DNS · Traceroute

```bash
cd Minho_DNS_Traceroute
gcc -std=c11 -Wall -Wextra -Wpedantic -o dns_capture dns_capture.c
gcc -std=c11 -Wall -Wextra -Wpedantic -o trace_capture trace_capture.c

sudo ./dns_capture                                    # 터미널 1 ("Listening on eth0" 확인 후)
dig @1.1.1.1 example.com A +notcp +tries=1 +time=3    # 터미널 2

sudo ./trace_capture                                  # 터미널 1
traceroute -n -I -N 1 -q 1 -w 1 1.1.1.1               # 터미널 2
```

### 이메일 (로컬 평문 실습)

Python 3.9 이상과 Tkinter 가 필요합니다. Gmail 외부 실습은 [Email-Protocol/README.md](Email-Protocol/README.md) 3장을 봅니다.

```bash
cd Email-Protocol
make -B
sudo ./mail_capture lo | python3 capture_gui.py    # 터미널 1 (macOS 는 lo0)
python3 receiver.py                                # 터미널 2
python3 sender.py                                  # 터미널 3, 본문 한 줄 입력
```

### BitTorrent (루프백 테스트)

실제 토렌트 캡처는 [bit_torrent/README.md](bit_torrent/README.md) 4-2 장과 [report_tip.md](bit_torrent/report_tip.md) 를 봅니다.

```bash
cd bit_torrent
make
sudo ./bt_sniffer -i lo -d | tee -i result_lo.txt   # 터미널 1
./test/bt_testgen                                   # 터미널 2 (sudo 필요 없음)

sudo bash scripts/capture.sh lo                     # 또는 tcpdump 저장까지 한 번에 (결과: captures/run_<날짜_시각>/)
```

## 4. WSL2 에서 캡처할 때 공통 주의 사항

- Windows 의 Wireshark 로 WSL `eth0` 트래픽을 보려면 `vEthernet (WSL (Hyper-V firewall))` 인터페이스를 고릅니다. WSL 의 `lo` 는 Windows 에서 보이지 않으므로 WSL 안에서 `sudo tcpdump -i lo -w 파일.pcap` 으로 저장한 뒤 Windows 에서 엽니다.
- 이 프로그램들은 Seq/Ack 실제 값을 출력합니다. Wireshark 에서 편집 → 설정 → Protocols → TCP → Relative sequence numbers 를 끄고 비교합니다.
- Wireshark 는 기본 설정에서 체크섬을 검증하지 않습니다(`[unverified]`). 검증을 켜거나 tcpdump `-v` 로 보면 송신 패킷의 체크섬이 "incorrect" 로 나오는데, 체크섬 계산을 네트워크 장치에 맡기는 기능(offload) 때문이며 오류가 아닙니다.
- 수신 패킷 길이가 MTU(1500)보다 크게 보이는 것은 여러 세그먼트를 합쳐 올리는 기능(GRO 등) 때문입니다. HTTP 1·2차 테스트에서는 이런 패킷을 Wireshark(Windows 쪽 캡처)가 IP 전체 길이 0 으로 기록했습니다.
- HTTPS·TLS 구간(HTTP 의 https, 이메일 외부 실습, HTTPS 트래커 등)은 암호화되어 내용을 해석할 수 없습니다.
- `/mnt/c` (Windows 폴더)에서 빌드·실행할 때 권한 문제가 생기면 폴더를 WSL 홈으로 복사해서 실행합니다.

## 5. 결과·보고서 자료 위치

| 파트 | 캡처 결과 | 검증·설명 자료 |
| --- | --- | --- |
| HTTP | `HTTP_Test_Result/sniff_wsl*.log`, `wsl*.pcapng` | [HTTP_Test_Result/README.md](HTTP_Test_Result/README.md) |
| DNS · Traceroute | `Minho_DNS_Traceroute/dns-trace.pcap`, 실행·검증 스크린샷 6장 | [Minho_DNS_Traceroute/README.md](Minho_DNS_Traceroute/README.md) 5~7장 |
| 이메일 | `Email-Protocol/첨부사진/` (터미널, Wireshark IMAP·POP3, SMTP·IMAP·POP3 캡처, 송수신 메일 화면 7장) | [Email-Protocol/README.md](Email-Protocol/README.md) 4장 |
| BitTorrent | `bit_torrent/captures/` (분석 결과 txt, 루프백 pcap, PNG, 보고서용 `전달용/`). 실제 토렌트 pcap 은 용량과 공인 IP 때문에 레포에 올리지 않음 | [bit_torrent/report_tip.md](bit_torrent/report_tip.md), [bit_torrent/README.md](bit_torrent/README.md) 4-4 장 |

## 6. 폴더 구조

```text
NetworkProject/
├── README.md                  이 문서 (팀 전체 안내)
├── HTTP_Code/
│   └── http_sniffer/          HTTP 스니퍼 소스 (main.c, http1.c, http2.c, hpack.c)
├── HTTP_Test_Result/          HTTP 1·2차 테스트 로그, Wireshark pcapng, 대조 분석
├── Minho_DNS_Traceroute/      DNS·Traceroute 소스, 검증 스크린샷, dns-trace.pcap
├── Email-Protocol/            메일 서버·캡처 (C), 송수신기·캡처 GUI (Python)
└── bit_torrent/               BitTorrent 분석기 소스, 테스트 생성기, 캡처·검증 스크립트, 캡처 결과, 보고서 팁
```
