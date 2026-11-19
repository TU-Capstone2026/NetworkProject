# HTTP_Test_Result — raw socket 스니퍼 vs Wireshark 비교 결과

같은 시간에 **raw socket으로 구현한 스니퍼(`http_sniffer`)**와 **Wireshark**로 동시에 캡처하고, 같은 패킷끼리 값을 비교한 결과.

| 파일 | 내용 |
|---|---|
| `sniff_wsl.log` | raw socket 스니퍼 출력 (`sudo ./http_sniffer eth0 -v`) |
| `wsl.pcapng` | Wireshark 캡처 파일 |

---

## 1. 테스트 환경

| 항목 | 값 |
|---|---|
| 일시 | 2026-11-19 22:25 (KST) |
| OS | Windows 11 (25H2, build 26200) + WSL2 Ubuntu |
| raw socket 캡처 | WSL `eth0` (172.23.252.163), `AF_PACKET / SOCK_RAW`, `-v` 옵션 |
| Wireshark 캡처 | Wireshark 4.6.9 (Dumpcap), 인터페이스 `vEthernet (WSL (Hyper-V firewall))`, 필터 `tcp port 80` |
| 요청 도구 | curl 8.18.0 |
| seq/ack 비교 기준 | 절대값 (Wireshark Relative sequence numbers 해제) |

## 2. 테스트 요청

| # | curl 명령 | 서버 IP | HTTP 버전 |
|---|---|---|---|
| 1 | `curl --http1.0 http://httpbin.org/get` | 44.209.237.184 | 1.0 |
| 2 | `curl --http1.1 http://httpbin.org/get` | 44.209.237.184 | 1.1 |
| 3 | `curl -d "id=student&pw=1234" http://httpbin.org/post` | 3.221.253.123 | 1.1 |
| 4 | `curl http://httpbin.org/status/404` | 44.209.237.184 | 1.1 |
| 5 | `curl --http2-prior-knowledge http://nghttp2.org/` | 139.162.123.134 | 2 |

## 3. 비교 방법
`wsl.pcapng`를 직접 파싱해서 각 TCP 패킷의 **출발지·목적지 IP, 포트, seq, ack, 플래그, 윈도, TTL, IP ID, IP 전체 길이, payload 길이**를 뽑고, `sniff_wsl.log`의 같은 패킷(출발지·포트·seq·ack·IP ID로 매칭)과 하나씩 대조했다.

---

## 4. 결과 요약

| 항목 | raw socket 스니퍼 | Wireshark | 결과 |
|---|---|---|---|
| TCP 패킷 수 | 60 | 60 | ✅ 일치 |
| IP·포트·seq·ack·플래그·윈도·TTL·IP ID | — | — | ✅ **60개 모두 일치** |
| IP 전체 길이 | — | — | 59개 일치, **1개 차이** (5장 참고) |
| 송신(OUT)·수신(IN) 구분 | 둘 다 출력 | 출발지 IP로 확인 | ✅ 일치 |

## 5. 항목별 비교

### 5-1. TCP 연결 설정 (요청 1, httpbin.org)

| 단계 | 방향 | raw socket 스니퍼 | Wireshark (절대 seq) |
|---|---|---|---|
| SYN | 172.23.252.163:41876 → 44.209.237.184:80 | seq=1896994750 ack=0 [SYN] | seq=1896994750 ack=0 [SYN] |
| SYN-ACK | 44.209.237.184:80 → 172.23.252.163:41876 | seq=1297739449 ack=1896994751 [SYN,ACK] | 동일 |
| ACK | 172.23.252.163:41876 → 44.209.237.184:80 | seq=1896994751 ack=1297739450 [ACK] | 동일 |

연결 해제(FIN → ACK → FIN → ACK)도 5개 연결 모두 같은 값으로 확인됨.

### 5-2. HTTP/1.x (요청 1~4)

| 요청 | raw socket 스니퍼 해석 | Wireshark(패킷 원본) 시작줄 | 결과 |
|---|---|---|---|
| 1 요청 | Method GET / URI `/get` / Version HTTP/1.0 | `GET /get HTTP/1.0` | ✅ |
| 1 응답 | HTTP/1.0 / 200 / OK, content-length 202 | `HTTP/1.0 200 OK` | ✅ |
| 2 요청 | GET / `/get` / HTTP/1.1 | `GET /get HTTP/1.1` | ✅ |
| 2 응답 | HTTP/1.1 / 200 / OK | `HTTP/1.1 200 OK` | ✅ |
| 3 요청 | POST / `/post` / HTTP/1.1, Body 18 bytes `id=student&pw=1234` | `POST /post HTTP/1.1` + 본문 `id=student&pw=1234` | ✅ |
| 3 응답 | HTTP/1.1 / 200 / OK, content-length 389 | `HTTP/1.1 200 OK` | ✅ |
| 4 요청 | GET / `/status/404` / HTTP/1.1 | `GET /status/404 HTTP/1.1` | ✅ |
| 4 응답 | HTTP/1.1 / 404 / Not Found | `HTTP/1.1 404 Not Found` | ✅ |

헤더(Host, User-Agent, Accept, Content-Type, Content-Length 등)도 원본 패킷 내용과 같음.

### 5-3. HTTP/2 (요청 5, nghttp2.org)

| 항목 | raw socket 스니퍼 | Wireshark(패킷 원본) | 결과 |
|---|---|---|---|
| 버전 판별 | `PRI * HTTP/2.0` connection preface 감지 | 패킷에 `PRI * HTTP/2.0 … SM` 존재 | ✅ |
| 요청 HEADERS | HPACK 디코딩 6개: `:method GET`, `:scheme http`, `:authority nghttp2.org`, `:path /`, `user-agent`, `accept` | 압축된 바이너리 28 bytes | ✅ (길이 일치) |
| 응답 HEADERS | HPACK 디코딩 14개: `:status 200`, `content-type text/html`, `content-length 6510`, `server nghttpx` 등 | 압축된 바이너리 224 bytes | ✅ (길이 일치) |
| 응답 DATA | 6510 bytes, 패킷 3개(1448+4344+960 bytes 구간)에 걸친 프레임을 재조립 | HTML 본문 (`<!DOCTYPE html>` …) | ✅ |
| HPACK 정확성 근거 | 디코딩된 `content-length: 6510` = 실제 DATA 프레임 길이 6510 | — | ✅ |

> Wireshark 화면의 HTTP2 헤더 해석(Decode As HTTP2)과 대조한 스크린샷은 보고서에 별도 첨부 예정.

---

## 6. 차이점 분석

| 패킷 | raw socket 스니퍼 | Wireshark | 원인 |
|---|---|---|---|
| nghttp2.org 응답 중간 패킷 (seq=36167763) | IP total_len = **4396** | IP total_len = **0** | 1500바이트 패킷 3개(1448×3 = 4344 bytes)가 하나로 합쳐진(segmentation offload) 패킷. Windows 쪽 캡처에는 길이 필드가 0으로 기록되고, WSL 커널은 합친 뒤 실제 길이를 넣음. **캡처 위치 차이**이며 나머지 필드(IP·포트·seq·ack·플래그)는 일치 |

기타 확인 사항
- **DNS(UDP 53)는 캡처되지 않음.** WSL의 DNS 터널링(dnsTunneling, Windows 11 22H2 이상 기본값)으로 DNS 질의가 eth0을 거치지 않기 때문 → DNS 담당 테스트 시 참고
- 스니퍼 경고(`!!` TCP gap, HPACK 실패, 버퍼 넘침) **0건**

## 7. 결론
raw socket 스니퍼는 실제 HTTP 서버(httpbin.org, nghttp2.org)와의 통신에서 **송신·수신 패킷을 모두 캡처**했고, **IP·TCP 헤더 값이 Wireshark와 60개 패킷 전부 일치**했다.
HTTP/1.0·1.1·2를 하나의 프로그램에서 자동 판별했으며, **메서드·URI·상태 코드·주요 헤더**를 HTTP/1.x는 텍스트 파싱, HTTP/2는 HPACK 디코딩으로 정확히 복원했다.
유일한 차이(IP 전체 길이 1건)는 캡처 위치에 따른 offload 표시 차이로 분석 결과에는 영향이 없다.
