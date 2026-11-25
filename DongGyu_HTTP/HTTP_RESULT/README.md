# HTTP_RESULT — HTTP/1.0 · 1.1 · 2 테스트 결과

## 1. 실행 방법

```bash
# 터미널 1 — 미니 Wireshark (curl보다 먼저 실행)
cd ~/http_sniffer && make
sudo ./http_sniffer eth0 -v 80

# 터미널 2 — 버전별로 하나씩 실행
curl -v --http1.0 http://www.example.com/                          # HTTP/1.0
curl -v --http1.1 http://httpforever.com/                          # HTTP/1.1
curl -v --http2-prior-knowledge -o /dev/null http://nghttp2.org/   # HTTP/2
```

Wireshark(Windows) 대조 시
- 인터페이스 `vEthernet (WSL (Hyper-V firewall))`, 표시 필터 `tcp.port == 80`
- 편집 → 기본 설정 → Protocols → TCP → Relative sequence numbers 해제
- HTTP/2는 분석 → 다른 형식으로 디코드 → TCP port 80 → HTTP2

## 2. 추천 스크린샷 (버전별 3장)

| 버전 | 파일 | 사진 설명 |
|---|---|---|
| HTTP/1.0 | `HTTP1.0/HTTP1.0_curl.png` | curl -v 화면 — `GET / HTTP/1.0` 요청, `HTTP/1.1 200 OK`·`Connection: close` 응답 |
| | `HTTP1.0/HTTP1.0_wireshark.png` | Wireshark — 포트 46452 연결 10개 패킷 (SYN → GET → 200 OK → FIN) |
| | `HTTP1.0/HTTP1.0_mini_wireshark.png` | 미니 Wireshark — 3-way handshake, 버전 판별(HTTP/1.x), GET 요청 헤더 |
| HTTP/1.1 | `HTTP1.1/HTTP1.1_curl.png` | curl -v 화면 — `GET / HTTP/1.1` 요청, `Transfer-Encoding: chunked`·`keep-alive` 응답 |
| | `HTTP1.1/HTTP1.1_wireshark.png` | Wireshark — 포트 33030 연결 12개 패킷 (응답 본문 2세그먼트, 클라 FIN 먼저) |
| | `HTTP1.1/HTTP1.1_mini_wireshark.png` | 미니 Wireshark — 3-way handshake, 버전 판별(HTTP/1.x), GET 요청 헤더 |
| HTTP/2 | `HTTP2/HTTP2_curl.png` | curl -v 화면 — `using HTTP/2`, stream 1 의사 헤더, `HTTP/2 200` 응답 |
| | `HTTP2/HTTP2_wireshark.png` | Wireshark(HTTP2 디코드) — Magic·SETTINGS·HEADERS·DATA·GOAWAY 프레임 20개 패킷 |
| | `HTTP2/HTTP2_mini_wireshark.png` | 미니 Wireshark — connection preface 감지, SETTINGS·WINDOW_UPDATE·HEADERS 프레임, HPACK 디코딩된 요청 헤더 |

Wireshark 원본 캡처는 `pcapng/`에 있음 (`HTTP1.0_wireshark.pcapng`, `HTTP1.1_wireshark.pcapng`, `HTTP2_wireshark.pcapng`).

## 3. 결과 비교

| | HTTP/1.0 | HTTP/1.1 | HTTP/2 |
|---|---|---|---|
| Wireshark 대조 (IP id·포트·Seq/Ack·Flags) | 10/10 일치 | 12/12 일치 | 20/20 일치 |
| 버전 판별 | 텍스트 시작줄 | 텍스트 시작줄 | connection preface |
| 헤더 | 평문 | 평문 | 바이너리 프레임 + HPACK |
| 본문 끝 판단 | 서버 FIN | 마지막 청크(0) | DATA END_STREAM |
| 연결 종료 | 서버가 먼저 FIN | 클라가 먼저 FIN | GOAWAY 후 클라 FIN |

참고: window 값은 스니퍼가 헤더 원값(예: 126), Wireshark 목록이 배율 적용값(예: 64512)을 보여서 달라 보이지만 원값은 같음.
