# http_sniffer — 미니 Wireshark (HTTP/1.0 · 1.1 · 2)

raw socket(`AF_PACKET`)으로 송신·수신 패킷을 캡처해서 **Ethernet → IPv4 → TCP/UDP → HTTP** 순서로 분석하는 C 프로그램.
TCP 연결마다 첫 데이터를 보고 HTTP 버전을 판별해 HTTP/1.x 파서 또는 HTTP/2 파서로 넘긴다.

```
raw socket 캡처 → Ethernet → IPv4 → TCP/UDP → 연결별 seq 추적
   → HTTP 버전 판별 ┬ "GET / POST … / HTTP/1."  → HTTP/1.0 · 1.1 (텍스트 파싱)
                    └ "PRI * HTTP/2.0" preface  → HTTP/2 (프레임 재조립 + HPACK)
```

## 1. 파일별 역할 (`http_sniffer/` 폴더)

| 파일 | 담당 버전 | 역할 |
|---|---|---|
| `main.c` | 공통 | raw socket 캡처, Ethernet·IP·TCP/UDP 헤더 출력, 송신(OUT)/수신(IN) 구분, TCP 연결설정(SYN)·해제(FIN) 표시, 연결별 seq 추적, **HTTP 버전 판별 후 파서 분기** |
| `http1.c` / `http1.h` | **HTTP/1.0 · 1.1** | 시작줄(메서드·URI·버전 / 상태코드)·헤더·본문 파싱. 본문 끝 판단: `Content-Length` / `chunked`(마지막 청크 0) / 연결 종료(FIN) |
| `http2.c` / `http2.h` | **HTTP/2** | connection preface 확인, 프레임(9바이트 헤더 + 페이로드) 재조립, 프레임 타입별 출력(SETTINGS·HEADERS·DATA·WINDOW_UPDATE·GOAWAY 등) |
| `hpack.c` / `hpack.h` | **HTTP/2** | HPACK(RFC 7541) 디코더 — HEADERS 블록을 `:method` `:path` `:status` 등 헤더로 복원 (정적·동적 테이블, 허프만) |
| `hpack_tables.h` | **HTTP/2** | RFC 7541 정적 테이블(61개)·허프만 코드표(256개) |
| `Makefile` | 공통 | `make` → `http_sniffer` 생성, `make clean` → 삭제 |

## 2. 실행 방법 (WSL)

```bash
sudo apt install -y build-essential curl
cp -r <레포>/DongGyu_HTTP/HTTP_Code/http_sniffer ~/http_sniffer   # WSL 홈으로 복사해서 실행
cd ~/http_sniffer && make

# 터미널 1 — 스니퍼 (curl보다 먼저 실행: HTTP/2 HPACK 상태가 연결 처음부터 쌓여야 함)
sudo ./http_sniffer eth0 -v 80

# 터미널 2 — 버전별 요청
curl -v --http1.0 http://www.example.com/
curl -v --http1.1 http://httpforever.com/
curl -v --http2-prior-knowledge -o /dev/null http://nghttp2.org/
```

| 옵션 | 의미 |
|---|---|
| `eth0` | 캡처할 인터페이스 (`ip a`로 확인) |
| `-v` | 데이터 없는 ACK도 출력 → 연결설정(SYN→SYN-ACK→ACK)·해제(FIN→ACK) 전 과정 표시 |
| `80` | 분석할 HTTP 포트 (생략 시 80·8080·8000) |

- 모두 평문 `http://`로 접속 (`https://`는 암호화되어 분석 불가)
- HTTP/2는 반드시 `--http2-prior-knowledge` (스니퍼는 preface로 HTTP/2를 판별, `--http2`의 Upgrade 방식은 미지원)
- 테스트 결과(스크린샷·pcapng)는 `../HTTP_RESULT/`

## 3. 한계
- IPv4만 지원, TCP 순서 뒤바뀜은 재정렬하지 않고 gap 경고 후 계속 분석
- HTTPS(TLS), HTTP/3(QUIC)는 범위 밖
- SETTINGS 8·9번 등 RFC 9113 이후 추가된 설정 ID는 이름 대신 `?(번호)`로 표시
