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
| Traceroute | `sudo ./trace_capture` | `traceroute -n -I -N 1 -q 1 -w 1 1.1.1.1` |

캡처 프로그램에 `Listening on eth0`가 뜬 뒤 실험 명령을 실행한다. 캡처는 Ctrl+C로 종료한다.

## 실험 결과

- DNS는 `1.1.1.1:53`에 `example.com`의 A 레코드를 질의했다. IPv4 주소와 UDP 포트, Transaction ID, QR, QNAME, QTYPE을 읽고 압축 이름과 A 레코드를 해석했다. 예시 ID `40568`(`0x9e78`)과 응답 주소 `104.20.23.154`, `172.66.147.243`이 `dig` 및 Wireshark에서 일치했다.
- Traceroute는 `1.1.1.1`로 보낸 ICMP Echo Request의 IPv4 TTL을 읽고, 응답의 출발지 IP와 ICMP Type·Code를 분석했다. Echo ID와 Sequence로 탐색 패킷과 응답을 연결했다. 첫 요청은 `ID=49900 Seq=1`, `TTL=1`이었고, 첫 홉 `172.25.128.1`에서 Time Exceeded(Type 11, Code 0)가 돌아왔다. 목적지에서는 Echo Reply(Type 0, Code 0)를 확인했다.

| Wireshark 표시 필터 | 비교 대상 |
| --- | --- |
| `dns.id == 40568` | 예시 DNS 질의와 응답 |
| `icmp.ident == 49900 && icmp.seq == 1` | 첫 탐색 패킷과 대응하는 ICMP 응답 |

재실행 시 ID, 경로, 응답 값이 달라질 수 있다.
