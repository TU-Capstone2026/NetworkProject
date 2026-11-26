# DNS·Traceroute 패킷 캡처

Ubuntu(WSL)의 `eth0`에서 C 프로그램이 `AF_PACKET` Raw Socket으로 패킷을 송수신 방향별로 캡처한다. 실험 트래픽은 `dig`와 `traceroute`로 발생시켰고, 같은 패킷을 Wireshark에서 대조했다.

## 빌드와 실행

```bash
gcc -std=c11 -Wall -Wextra -Wpedantic -o dns_capture dns_capture.c
gcc -std=c11 -Wall -Wextra -Wpedantic -o trace_capture trace_capture.c
```

| 실험 | 캡처 터미널 | 별도의 Ubuntu 터미널 |
| --- | --- | --- |
| DNS | `sudo ./dns_capture` | `dig @1.1.1.1 example.com A +notcp +tries=1 +time=3` |
| Traceroute | `sudo ./trace_capture` | `traceroute -4 -n -N 1 -q 1 -w 2 -m 30 -p 33434 1.1.1.1` |

캡처 프로그램에 `Listening on eth0`가 뜬 뒤 실험 명령을 실행한다. 캡처는 Ctrl+C로 종료한다.

## UDP Traceroute 캡처

현재 trace_capture.c는 eth0에서 1.1.1.1로 전송하는 IPv4 UDP 탐색(목적지 포트 33434~33534)을 기록한다. ICMP 오류 안에 인용된 로컬 IP와 UDP 포트 쌍을 송신 기록과 대조해 원래 TTL을 표시한다. 첫 홉은 ICMP 11/0, 목적지의 닫힌 포트는 ICMP 3/3으로 확인한다.

별도 WSL 터미널에서 다음 명령을 먼저 실행하고 탐색이 끝나면 Ctrl+C로 저장한다.

```bash
sudo tcpdump -p -i eth0 -s 0 -w - '(udp and dst host 1.1.1.1 and dst portrange 33434-33534) or icmp' > trace-udp.pcap
```

7쪽에는 TTL 1의 TX와 대응 RX, 목적지가 보낸 3/3과 대응 TX를 사용한다. Wireshark에서 송신 UDP 포트와 수신 ICMP 안의 원래 UDP 포트를 대조한다. 응답이 없는 홉은 실제 실행 결과대로 기록한다.

## 기존 실험 결과 (DNS 및 ICMP Echo 방식)

이하 Traceroute 설명·함수명·발표 문답과 기존 dns-trace.pcap은 이전 `-I` 실험 기록이다. UDP 방식 제출 자료는 새로 수집한다.

- DNS는 `1.1.1.1:53`에 `example.com`의 A 레코드를 질의했다. IPv4 주소와 UDP 포트, Transaction ID, QR, QNAME, QTYPE을 읽고 압축 이름과 A 레코드를 해석했다. 예시 ID `40568`(`0x9e78`)과 응답 주소 `104.20.23.154`, `172.66.147.243`이 `dig` 및 Wireshark에서 일치했다.
- Traceroute는 `1.1.1.1`로 보낸 ICMP Echo Request의 IPv4 TTL을 읽고, 응답의 출발지 IP와 ICMP Type·Code를 분석했다. Echo ID와 Sequence로 탐색 패킷과 응답을 연결했다. 첫 요청은 `ID=49900 Seq=1`, `TTL=1`이었고, 첫 홉 `172.25.128.1`에서 Time Exceeded(Type 11, Code 0)가 돌아왔다. 목적지에서는 Echo Reply(Type 0, Code 0)를 확인했다.

| Wireshark 표시 필터 | 비교 대상 |
| --- | --- |
| `dns.id == 40568` | 예시 DNS 질의와 응답 |
| `icmp.ident == 49900 && icmp.seq == 1` | 첫 탐색 패킷과 대응하는 ICMP 응답 |

재실행 시 ID, 경로, 응답 값이 달라질 수 있다.

---

## 처음 읽는 사람을 위한 실험 설명

이 실험에서는 두 가지를 확인했다. DNS에서는 **도메인 이름을 물어보면 어떤 IPv4 주소가 돌아오는지**, Traceroute에서는 **목적지까지 가는 도중 어떤 라우터가 응답하는지**를 봤다. Ubuntu(WSL)의 `eth0`에서 송신과 수신을 모두 캡처하고, C 프로그램의 출력을 표준 명령과 Wireshark로 대조했다.

### 1. 기본 용어

| 용어 | 뜻 | 이 실험에서 보는 것 |
| --- | --- | --- |
| 패킷 | 네트워크에서 전달하는 데이터 단위. 이 문서에서는 넓은 의미로 사용한다. | DNS 요청·응답, ICMP 요청·응답 |
| 헤더 | 데이터 앞에 붙는 제어 정보 | IPv4의 출발지·목적지 IP, UDP의 포트, DNS의 ID |
| 페이로드 | 현재 계층의 헤더 뒤에서 그 계층이 운반하는 데이터 | UDP 페이로드는 DNS 메시지 전체다. |
| 이더넷 프레임 | 이더넷에서 전달하는 단위 | `eth0`의 캡처에서 이더넷 헤더 뒤에 IPv4 헤더가 온다. |
| MAC 주소 | 이더넷 링크에서 프레임을 전달할 때 쓰는 주소 | Wireshark의 **Ethernet II**에서 볼 수 있다. |
| IPv4 주소 | 네트워크를 통해 데이터를 보낼 때 사용하는 출발지·목적지 주소 | DNS 서버와 Traceroute 목적지로 `1.1.1.1`을 사용했다. |
| 포트 | 같은 IP에서 UDP나 TCP 통신을 구분하는 번호 | DNS 서버는 UDP `53`, 클라이언트는 이 실험에서 임시 포트 `40204`를 사용했다. |
| UDP | 포트를 사용해 데이터를 보내는 전송 계층 프로토콜 | 이 실험의 DNS 요청·응답을 운반했다. |
| ICMP | IP 통신에서 오류나 진단 정보를 전달하는 프로토콜 | Echo Request, Time Exceeded, Echo Reply를 확인했다. |
| TX / RX | 캡처하는 장치 기준의 송신 / 수신 | TX는 WSL에서 나가는 프레임, RX는 들어오는 프레임이다. |
| 홉 | 패킷이 이동하는 경로에서 세는 한 단계 | Traceroute 출력의 행 번호로 표시된다. |
| RTT | 요청을 보낸 뒤 대응하는 응답이 돌아올 때까지 걸린 시간 | Traceroute가 각 응답 옆에 밀리초(`ms`)로 표시한다. |

DNS 프레임은 **이더넷 → IPv4 → UDP → DNS** 순으로 읽는다. Traceroute의 ICMP 프레임은 **이더넷 → IPv4 → ICMP** 순으로 읽는다. Wireshark 아래쪽의 항목이 이 순서로 나타난다.

### 2. 프로그램과 도구의 역할

| 도구 | 하는 일 |
| --- | --- |
| `dig` | 지정한 DNS 서버에 질의를 보내고 응답을 출력한다. |
| `traceroute` | TTL을 다르게 설정한 탐색 패킷을 보내고 홉별 응답을 출력한다. |
| `dns_capture.c` | 송수신 프레임에서 DNS 트래픽을 골라 주소, 포트, 질의 이름과 A 레코드를 읽는다. |
| `trace_capture.c` | Traceroute에 쓰인 송신 요청과 수신 응답을 골라 ID와 순서 번호로 연결한다. |
| `tcpdump` | 실험 중의 프레임을 `dns-trace.pcap` 파일에 저장했다. |
| Wireshark | 저장된 `.pcap` 파일을 열어 프레임과 헤더 필드를 확인한다. |

`eth0`은 이 실험에서 사용한 WSL의 네트워크 인터페이스다. 두 C 프로그램은 리눅스의 `AF_PACKET`과 `SOCK_RAW`로 이더넷 헤더를 포함한 프레임을 읽는다. `ETH_P_ALL`로 소켓을 열고 `bind()`로 `eth0`에 지정한 다음, `recvfrom()`으로 프레임과 부가 정보를 받는다. 이 부가 정보의 `sll_pkttype`이 `PACKET_OUTGOING`이면 TX로 처리한다. 실험에서는 패킷 소켓을 열 권한을 얻기 위해 `sudo`로 실행했다.

### 3. DNS 실험

**DNS는 도메인 이름에 대한 정보를 찾는 시스템이다. A 레코드는 도메인 이름에 연결된 IPv4 주소 하나를 담은 DNS 레코드다.** 같은 이름에 A 레코드가 여러 개 있으면 응답에서 IPv4 주소를 여러 개 받을 수 있다.

이 실험에서 `example.com`은 **질의한 도메인**, `1.1.1.1`은 **질의를 받은 DNS 서버**다. `dig`가 `1.1.1.1:53`으로 “`example.com`의 A 레코드를 알려 달라”는 DNS 메시지를 보냈다. `dig` 명령의 `A`는 조회 유형을 고르고, `+notcp`는 UDP로 질의하도록 지정한다. `+tries=1`은 시도 횟수를 한 번으로 설정하고 `+time=3`은 타임아웃을 3초로 설정한다.

| 화면의 필드 | 뜻 | 이 실험의 값 |
| --- | --- | --- |
| `Source / Destination IP` | 패킷을 보낸 쪽과 받는 쪽의 IP | 요청은 WSL → `1.1.1.1`, 응답은 반대 방향 |
| UDP 출발지·목적지 포트 | 송신 측과 수신 측의 포트 | 요청은 `40204 → 53`, 응답은 `53 → 40204` |
| `ID` / Transaction ID | 질의와 응답을 대조할 때 쓰는 DNS 헤더 값 | 양쪽 모두 `40568`이며 Wireshark에는 `0x9e78`로 표시된다. |
| `QR` | 질의인지 응답인지 나타내는 1비트 | 질의는 `0`, 응답은 `1` |
| `QNAME` | 질의 대상 이름 | `example.com` |
| `QTYPE` | 요청한 DNS 레코드 유형 | `1 (A)` |
| `QDCOUNT` / `QUERY` | 질문 항목 수 | `1` |
| `ANCOUNT` / `ANSWER` | 응답의 Answer 섹션에 담긴 레코드 수 | `2` |
| `NOERROR` | 서버가 보낸 DNS 응답 코드 | 질의가 오류 없이 처리됐음을 뜻한다. 반환된 레코드는 Answer 섹션에서 확인한다. |
| `IN` | DNS의 인터넷 클래스 | `dig`의 질문과 응답 레코드에 표시된다. |
| DNS 레코드의 `TTL` | 해당 레코드를 캐시에 보관할 수 있는 시간. 단위는 초다. | `dig`의 Answer 섹션에서 `IN` 앞에 표시된다. |
| `OPT` | EDNS 옵션을 전달하는 의사 레코드 | `dig`의 OPT 영역과 Wireshark Info에 표시된다. |

`dig` 응답 헤더의 `opcode: QUERY`는 일반 조회 연산이라는 뜻이다. 그 메시지가 응답이라는 사실은 `flags`의 `qr` 또는 C 프로그램의 `QR=1`에서 확인한다. `rd`는 클라이언트가 재귀 조회를 요청했다는 표시이고, `ra`는 응답한 서버가 재귀 조회를 지원한다는 표시다.

**저장된 실험 결과**에서는 질의와 응답의 ID가 모두 `40568`이고 UDP 포트 방향이 서로 뒤집힌다. 응답의 A 레코드 두 개는 `104.20.23.154`와 `172.66.147.243`이다. C 프로그램과 `dig`, Wireshark에서 같은 값을 확인했다. C 프로그램에 나온 `52`바이트와 `72`바이트는 DNS 메시지 길이이고, Wireshark 목록의 `94`바이트와 `114`바이트는 이 캡처의 전체 프레임 길이다. 각각 이더넷 14바이트, IPv4 20바이트, UDP 8바이트를 더하면 일치한다.

**추가로 실행한 `naver.com` 실험**에서는 같은 DNS 서버로 A 레코드를 질의했다. C 프로그램과 `dig` 양쪽에서 ID `39736`과 A 레코드 네 개(`223.130.200.219`, `223.130.200.236`, `223.130.192.247`, `223.130.192.248`)가 일치했다. 이 결과는 별도로 실행한 실험이고, 저장된 `dns-trace.pcap`의 DNS 패킷은 `example.com` 질의·응답이다.

#### `dns_capture.c`를 읽는 순서

| 함수 또는 구조체 | 하는 일 |
| --- | --- |
| `main()` | 소켓을 열고 프레임을 계속 받는다. 송수신 방향을 확인하고 UDP 해석과 DNS 필터를 통과한 프레임을 출력 함수로 보낸다. |
| `read_u16()` | 연속한 두 바이트를 네트워크 바이트 순서로 읽어 정수 하나로 합친다. DNS ID, 포트처럼 2바이트인 값에 쓴다. |
| `decode_udp()` / `UdpPacket` | 이더넷·IPv4·UDP를 차례대로 확인한다. 주소, 포트, DNS 페이로드 위치와 길이를 구조체에 담는다. |
| `is_dns_exchange()` | 송신이면 목적지, 수신이면 출발지가 `1.1.1.1:53`인 UDP 프레임을 고른다. |
| `decode_dns_header()` / `DnsHeader` | DNS 고정 헤더 12바이트가 있는지 확인하고 ID, QR, 질문 수, 응답 레코드 수를 읽는다. |
| `decode_dns_name()` | DNS 메시지의 이름을 라벨 단위로 읽고, 압축 포인터가 있으면 가리키는 곳의 이름을 이어서 읽는다. |
| `print_dns_sections()` | 질문에서 QNAME과 QTYPE을 출력한다. Answer 섹션을 돌면서 IN 클래스의 A 레코드이고 데이터 길이가 4바이트인 항목을 IPv4 주소로 출력한다. |
| `print_packet()` | IP를 읽을 수 있는 문자열로 변환하고 TX/RX, 주소와 포트, 페이로드 길이, ID, QR과 DNS 섹션을 출력한다. |

`example.com`은 DNS 메시지에서 길이 `7`과 `example`, 길이 `3`과 `com`, 종료값 `0`의 순서로 표현할 수 있다. 응답에서 같은 이름을 다시 쓸 때는 앞서 나온 이름의 위치를 가리키는 **압축 포인터**를 사용할 수 있다. 예를 들어 `c0 0c`는 DNS 메시지 시작을 기준으로 12바이트 떨어진 위치를 가리킨다. 이름을 읽는 동안 `cursor`는 현재 읽는 위치, `resume`은 포인터 처리 후 원래 레코드에서 이어 읽을 위치, `limit`은 탐색 범위의 상한을 뜻한다. 포인터를 따라갈 때마다 상한을 앞당겨 순환 참조를 막는다. 질문에서는 이름 뒤의 QTYPE·QCLASS로, 응답에서는 이름 뒤의 TYPE·CLASS·TTL·RDLENGTH를 거쳐 실제 레코드 데이터로 이동한다.

### 4. Traceroute 실험

**Traceroute는 탐색 패킷의 IPv4 TTL을 조금씩 높여 가며 각 단계에서 응답한 장비를 확인한다.** IPv4 TTL은 라우터를 지날 때 일반적으로 1씩 감소한다. 전달 도중 TTL이 소진되면 라우터가 ICMP Time Exceeded를 돌려보낼 수 있다. 탐색 패킷이 목적지에 도착하면 목적지가 ICMP Echo Reply로 응답할 수 있다.

| 구분 | ICMP Type / Code | 화면에서 의미하는 것 |
| --- | --- | --- |
| Echo Request | `8 / 0` | 내 WSL이 보낸 탐색 패킷 |
| Time Exceeded | `11 / 0` | 해당 라우터까지 갔지만 전달 도중 TTL이 소진됨 |
| Echo Reply | `0 / 0` | 목적지가 탐색 요청에 응답함 |

| 옵션 | 뜻 |
| --- | --- |
| `-n` | 라우터 주소를 이름으로 변환하지 않고 IP로 표시한다. |
| `-I` | ICMP Echo Request를 탐색 패킷으로 사용한다. |
| `-N 1` | 동시에 진행 중인 탐색 요청을 최대 하나로 제한한다. |
| `-q 1` | TTL 값마다 탐색 패킷을 하나씩 보낸다. |
| `-w 1` | 이 실행에서 탐색 응답 대기 시간의 상한을 1초로 둔다. |

1. 첫 탐색은 `TTL=1`, `ID=49900`, `Seq=1`이었다. 첫 홉 `172.25.128.1`에서 Time Exceeded를 보냈다.
2. TTL 11의 요청도 송신됐지만 해당 실행에서 대기 시간 안에 응답이 확인되지 않아 Traceroute가 11번째 홉을 `*`로 표시했다. 이후 홉은 계속 확인됐다.
3. TTL 13의 요청에는 목적지 `1.1.1.1`이 Echo Reply로 응답했다. Traceroute 목록에 나타난 13번째 홉과 C 로그의 `Probe TTL=13`이 대응한다.

Time Exceeded에는 **라우터가 새로 만든 바깥 IPv4·ICMP 헤더**와 **원래 요청의 IPv4 헤더 및 ICMP 앞부분**이 들어 있다. 바깥 IPv4 출발지에서 응답한 라우터의 IP를 읽고, 안쪽에 인용된 Echo Request에서 ID와 순서 번호(`Seq`)를 읽는다. 코드가 표시한 `Probe TTL`은 송신할 때 저장한 초기 TTL 값이다. Wireshark에서 응답의 바깥 IPv4 TTL은 그 응답 패킷 자체의 값으로 따로 읽는다.

#### `trace_capture.c`를 읽는 순서

| 함수 또는 구조체 | 하는 일 |
| --- | --- |
| `main()` | `eth0`에서 프레임을 읽고 ICMP로 해석한다. 대상 주소로 나가는 Echo Request는 기록하고, 들어오는 응답은 `print_response()`로 보낸다. |
| `read_u16()` | IPv4 길이, ICMP ID와 순서 번호 등 2바이트 값을 읽는다. |
| `decode_ipv4_icmp()` / `IcmpPacket` | 프레임의 헤더와 길이를 검사하고 바깥 IPv4의 주소, TTL과 ICMP 위치를 가져온다. |
| `record_probe()` / `Probe` | 송신 요청마다 로컬 IP, ICMP ID, 순서 번호, 초기 TTL을 저장한다. 최근 128개까지 순환 배열에 보관한다. |
| `quoted_echo_request()` | Time Exceeded 안에서 인용된 원래 요청의 IPv4와 ICMP 헤더를 검사하고 Echo Request 위치를 찾는다. |
| `find_probe_ttl()` | 로컬 IP, ID, 순서 번호로 최근 요청을 찾아 저장한 TTL을 반환한다. |
| `print_response()` | Time Exceeded면 인용된 요청에서, Echo Reply면 응답 헤더에서 ID와 순서 번호를 얻는다. 일치한 요청의 초기 TTL과 응답 출발지 등을 출력한다. |

두 프로그램 모두 수신한 바이트를 읽기 전에 필요한 길이가 있는지 확인한다. IPv4 헤더는 길이 필드(IHL)를 읽어 다음 헤더의 시작을 계산한다. 인터넷 헤더의 2바이트 값은 상위 바이트가 먼저 오므로, 예를 들어 DNS ID `9e 78`은 `0x9e78`, 즉 십진수 `40568`로 해석한다.

### 5. Wireshark로 캡처 파일 확인하기

[캡처 파일 열기](dns-trace.pcap)

| 확인할 것 | 표시 필터 | 읽는 순서 |
| --- | --- | --- |
| DNS 질의·응답 | `dns.id == 40568` | 프레임 1과 2를 선택한다. **Internet Protocol Version 4**와 **User Datagram Protocol**에서 주소와 포트를, **Domain Name System**에서 ID, 질문, 응답 레코드를 확인한다. |
| 첫 홉 | `icmp.ident == 49900 && icmp.seq == 1` | 프레임 3의 **IPv4**에서 TTL 1을 확인한다. 프레임 4의 **Internet Control Message Protocol**에서 Time Exceeded를 확인하고, 그 아래 인용된 요청의 ID와 순서 번호를 본다. |
| 목적지 응답 | `icmp.type == 0 && ip.src == 1.1.1.1` | Echo Reply에서 목적지 주소와 순서 번호 13을 확인한다. |

첫 Echo Request 옆의 `no response found!`는 Wireshark가 대응하는 Echo Reply를 찾지 못했다는 표시다. 바로 다음 프레임에는 첫 홉이 보낸 **Time Exceeded**가 있다. Traceroute에서 첫 홉을 알아낸 근거는 이 Time Exceeded의 출발지 IP다.

캡처 실행 화면과 Wireshark 화면을 나란히 볼 때는 DNS의 **Transaction ID와 포트**, Traceroute의 **ICMP ID와 순서 번호**를 기준으로 같은 패킷을 찾으면 된다. 표시 필터는 화면에 보이는 항목만 좁히므로 필터를 지우면 전체 캡처를 다시 볼 수 있다.

### 6. 두 실험을 설명할 때 자주 나오는 질문

**DNS의 TTL과 Traceroute의 TTL은 각각 무엇을 세나요?** DNS 레코드 TTL은 캐시에 보관할 수 있는 시간(초)이다. Traceroute에서 확인하는 IPv4 TTL은 전달 도중 라우터가 줄이는 IPv4 헤더 값이다.

**DNS의 ID와 Traceroute의 ID를 어떻게 썼나요?** DNS에서는 같은 ID와 서로 뒤집힌 IP·포트를 출력에서 대조했다. Traceroute 코드에서는 송신 요청을 배열에 저장하고, 수신 응답의 ICMP ID와 순서 번호를 해당 로컬 IP와 함께 조회해 초기 TTL을 복원했다.

**하나의 도메인에 왜 여러 IPv4 주소가 나오나요?** 한 도메인 이름에 여러 A 레코드를 등록할 수 있다. 이 실험의 `example.com` 응답에는 A 레코드가 두 개 있었다.

**왜 도메인을 바꿔도 캡처 코드가 동작하나요?** DNS 프로그램은 도메인 이름을 필터 조건으로 두지 않는다. `1.1.1.1:53`과 주고받은 UDP 패킷을 고른 뒤 실제 DNS 메시지에서 이름을 읽는다.

**같은 주소를 대상으로 했는데 두 실험은 무엇이 다른가요?** DNS에서 `1.1.1.1`은 `example.com`의 주소를 물어본 서버다. Traceroute에서 `1.1.1.1`은 ICMP 탐색으로 도착 여부를 확인한 목적지다.

### 7. 발표 예상 질문과 답변

#### 기본 개념과 구현

**Q. 직접 구현한 부분은 어디까지인가요?**  
`dig`와 `traceroute`로 실험 트래픽을 발생시켰습니다. 제가 C로 구현한 부분은 WSL의 `eth0`에서 송수신 프레임을 받아 필요한 프로토콜을 골라내고 헤더를 읽어 출력하는 기능입니다. Traceroute에서는 송신 요청과 수신 응답을 연결해 출발할 때의 TTL도 표시했습니다.

**Q. Raw Socket을 쓴 이유와 송신·수신을 구분한 방법은 무엇인가요?**  
리눅스의 `AF_PACKET`과 `SOCK_RAW`로 이더넷 헤더를 포함한 프레임을 받아 IP, UDP 또는 ICMP 헤더를 직접 해석하기 위해 사용했습니다. `recvfrom()`으로 받은 프레임의 부가 정보에서 `PACKET_OUTGOING`이면 송신으로 처리했습니다.

**Q. 짧거나 잘린 패킷을 받으면 어떻게 처리하나요?**  
헤더를 읽기 전에 실제로 받은 바이트 수를 확인합니다. IPv4 헤더에 기록된 전체 길이, 헤더 길이(IHL), DNS의 경우 UDP 길이도 확인합니다. 필요한 바이트가 부족하거나 길이 정보가 맞지 않으면 해당 부분의 해석을 중단합니다.

#### DNS

**Q. `dig @1.1.1.1 example.com A`에서 각 항목은 무슨 뜻인가요?**  
`dig`는 DNS 서버에 질문을 보내고 답을 보여주는 명령입니다. `@1.1.1.1`은 질문을 받을 공개 DNS 서버, `example.com`은 질문할 도메인, `A`는 요청할 레코드 유형입니다. A 레코드 하나에는 IPv4 주소 하나가 들어 있습니다.

**Q. 같은 DNS 요청에 대한 응답이라는 걸 어떻게 확인했나요?**  
질의와 응답의 DNS ID가 모두 `40568`이었고, UDP 포트가 질의에서 `40204 → 53`, 응답에서 `53 → 40204`였습니다. `QR=0`은 질의, `QR=1`은 응답입니다. 이 값들을 캡처 출력에서 대조했습니다. Wireshark의 `0x9e78`도 같은 ID를 16진수로 표시한 값입니다.

**Q. DNS 이름 압축은 무엇이고 어떻게 읽었나요?**  
응답에서 같은 도메인 이름을 반복해 적는 대신 앞에 기록된 이름의 위치를 가리킬 수 있습니다. 코드는 그 위치로 이동해 이름을 읽고, 원래 위치에서 포인터 바로 다음 바이트부터 레코드 해석을 이어갑니다.

**Q. 다른 도메인이나 IPv6 주소 조회도 분석할 수 있나요?**  
도메인 이름은 패킷에서 읽기 때문에 같은 DNS 서버에 `naver.com`처럼 다른 이름을 물어봐도 캡처됩니다. 현재 코드는 `1.1.1.1:53`과 주고받는 IPv4 UDP 패킷을 대상으로 하고, Answer 섹션의 주소는 A 레코드에서 출력합니다. IPv6 주소가 담긴 AAAA 레코드의 주소 출력은 구현 범위 밖입니다.

#### Traceroute와 결과 검증

**Q. TTL이 1인데 첫 번째 라우터의 IP를 어떻게 알아내나요?**  
첫 번째 라우터에서 TTL이 소진되면 라우터가 ICMP Time Exceeded를 보낼 수 있습니다. 이때 **응답의 바깥 IPv4 헤더에 있는 출발지 주소**가 응답한 라우터의 주소입니다. 이번 실험에서는 `172.25.128.1`이 첫 번째 홉이었습니다.

**Q. 첫 라우터의 응답을 원래 요청과 어떻게 연결했나요?**  
송신할 때 로컬 IP, ICMP ID, 순서 번호, 초기 TTL을 저장합니다. Time Exceeded 내부에 인용된 원래 요청에서 ID와 순서 번호를 읽고, 응답의 목적지인 로컬 IP를 함께 사용해 기록을 찾습니다. 화면의 `Probe TTL=1`은 그 기록에 저장된 송신 당시 TTL입니다.

**Q. 11번째에 `*`가 떴는데 13번째에 어떻게 목적지에 도착했나요?**  
별표는 TTL 11로 보낸 탐색의 응답을 대기 시간 안에 받지 못했다는 뜻입니다. Traceroute는 TTL 값을 높인 새 요청을 계속 보냅니다. 이번 실험에서는 TTL 13으로 보낸 요청에 목적지 `1.1.1.1`의 Echo Reply가 돌아왔습니다.

**Q. Wireshark에서 어떤 값이 같아서 검증됐다고 판단했나요?**  
DNS는 `dns.id == 40568`로 질의와 응답을 찾고 UDP 포트, 질문 이름, A 레코드 두 개를 대조했습니다. Traceroute는 `icmp.ident == 49900 && icmp.seq == 1`로 첫 요청과 Time Exceeded를 찾고 요청의 TTL과 응답을 보낸 라우터의 IP를 비교했습니다.
