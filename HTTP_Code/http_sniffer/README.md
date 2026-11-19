# http_sniffer — 미니 Wireshark (HTTP/1.0 · 1.1 · 2 통합 스니퍼)

raw socket으로 송신·수신 패킷을 캡처해서 **Ethernet → IPv4 → TCP/UDP → HTTP** 순서로 분석하는 C 프로그램.
연결마다 첫 데이터를 보고 HTTP 버전을 자동으로 판별해서 HTTP/1.x 파서 또는 HTTP/2 파서(HPACK 포함)로 넘긴다.

```
raw socket 캡처 → Ethernet → IPv4 → TCP/UDP → 연결별 seq 추적
   → HTTP 버전 판별 ┬ HTTP/2   : 프레임 재조립 → HEADERS는 HPACK 디코딩
                    └ HTTP/1.x : 시작줄·헤더·본문 텍스트 파싱
```

---

## 1. 파일별 용도

| 파일 | 용도 |
|---|---|
| `main.c` | 프로그램 시작점. raw socket(`AF_PACKET`)으로 송수신 프레임을 받아 Ethernet·IP·TCP/UDP 헤더를 출력하고, TCP 연결별 seq를 추적(중복 제거·누락 경고)한 뒤 **HTTP 버전을 판별해서 파서로 분기** |
| `http1.c` | HTTP/1.0·1.1 텍스트 파서. 시작줄(메서드·URI·버전 / 상태 코드·Reason)·헤더·본문 출력. 본문은 `Content-Length` / `chunked` / 연결 종료(FIN)로 끝을 판단하고 여러 세그먼트에 걸쳐도 이어서 출력 |
| `http1.h` | HTTP/1 파서의 방향별 상태 구조체와 함수 선언 |
| `http2.c` | HTTP/2 프레임 파서. 방향별 버퍼에 쌓아 `9바이트 헤더 + 길이` 단위로 프레임을 자르고 타입별(DATA·HEADERS·SETTINGS·WINDOW_UPDATE·GOAWAY 등) 출력. HEADERS(+CONTINUATION) 블록을 모아 HPACK으로 넘김 |
| `http2.h` | HTTP/2 파서의 방향별 버퍼 구조체, connection preface, 함수 선언 |
| `hpack.c` | HPACK(RFC 7541) 디코더. 정수·허프만 디코딩, 정적 테이블(1~61)·동적 테이블(62~)로 `:method` `:path` `:status`와 헤더 복원 |
| `hpack.h` | HPACK 디코더의 테이블 구조체와 함수 선언 |
| `hpack_tables.h` | RFC 7541 부록 B 허프만 코드표(256개)와 부록 A 정적 테이블(61개) |
| `Makefile` | `make` → 실행 파일 `http_sniffer` 생성, `make clean` → 삭제 |
| `README.md` | 이 문서 (파일 용도·실행 방법·테스트 서버) |
| `verify_lo.log` | 개발 중 로컬(`lo`) 사전 점검 기록. **과제 테스트 결과 아님** — 실제 결과는 `../../HTTP_Test_Result/` |

### HTTP 버전 판별 규칙
- 클라이언트 첫 데이터가 `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` → **HTTP/2**
- `GET ` `POST ` … 또는 `HTTP/1.`로 시작 → **HTTP/1.x** (요청 시작줄의 버전으로 1.0 / 1.1 표시)

---

## 2. 실행 방법 (WSL)

> ⚠️ `/mnt/c/...`(Windows 폴더)에서 빌드·실행하면 실행 권한 문제가 생길 수 있으므로 **WSL 홈으로 복사해서** 실행한다.

```bash
# 1) 준비
sudo apt install -y build-essential curl
cp -r <레포>/HTTP_Code/http_sniffer ~/http_sniffer   # 이 폴더를 WSL 홈으로
cd ~/http_sniffer
make                                   # 경고 0개

# 2) Wireshark(Windows) 먼저 캡처 시작
#    인터페이스: vEthernet (WSL (Hyper-V firewall)) / 캡처 필터: tcp port 80
#    편집 → 기본 설정 → Protocols → TCP → Relative sequence numbers 해제

# 3) 터미널 1 — 스니퍼 (curl보다 먼저: HTTP/2 HPACK 상태가 연결 처음부터 쌓임)
sudo ./http_sniffer eth0 -v | tee sniff_wsl.log

# 4) 터미널 2 — curl (아래 테스트 서버 표 참고, 하나씩 실행)

# 5) Ctrl+C로 종료 → Wireshark 저장(wsl.pcapng) → 결과를 레포의 HTTP_Test_Result/로 복사
```

| 옵션 | 의미 |
|---|---|
| `eth0` | 캡처할 인터페이스 (`ip a`로 확인) |
| `-v` | 데이터 없는 ACK도 출력 → TCP 연결설정(SYN→SYN-ACK→ACK)·해제(FIN→ACK) 전 과정 표시 |
| 포트 번호 | 직접 지정 시 (기본 80 8080 8000) — 예: `sudo ./http_sniffer eth0 80` |

---

## 3. 테스트 서버 (11/19 1차 테스트 완료)

모두 **평문 `http://`** 로 접속한다 (`https://`는 암호화되어 분석 불가).

| HTTP 버전 | 서버 | curl 명령 | 확인 항목 |
|---|---|---|---|
| HTTP/1.0 | httpbin.org | `curl --http1.0 http://httpbin.org/get` | GET·URI·버전 1.0 |
| HTTP/1.1 | httpbin.org | `curl --http1.1 http://httpbin.org/get` | 버전 1.1 |
| HTTP/1.1 | httpbin.org | `curl -d "id=student&pw=1234" http://httpbin.org/post` | POST·본문 평문 노출 |
| HTTP/1.1 | httpbin.org | `curl http://httpbin.org/status/404` | 상태 코드 404 |
| HTTP/2 | nghttp2.org | `curl --http2-prior-knowledge http://nghttp2.org/` | connection preface·프레임·HPACK 헤더 |

- HTTP/2는 평문(h2c)을 받는 공개 서버가 드물어 nghttp2.org를 사용하며, 반드시 `--http2-prior-knowledge` 옵션을 쓴다 (`--http2`의 Upgrade 방식은 미지원).


---

## 4. 앞으로 테스트 예정인 HTTP 테스트 서버

모두 평문 `http://`. 사이트 사정으로 HTTPS로 리다이렉트되거나 내려갈 수 있으니 **테스트 전에 `curl -sI <URL>`로 먼저 확인**한다.

### 4-1. HTTP/1.0 · 1.1 — 일반 사이트

| URL | curl 예시 | 확인 목적 | 근거 |
|---|---|---|---|
| http://example.com/ | `curl --http1.0 http://example.com/` | 다른 서버에서 1.0 교차 확인 | IANA example.com은 아직 평문 HTTP 버전이 있음 ([HN 댓글](https://frontpage-app.vercel.app/newest/45736499)) |
| http://httpforever.com/ | `curl --http1.1 http://httpforever.com/` | 큰 응답 → 본문 이어받기 | "A reliably insecure connection", 누구나 사용 가능 ([HTTP Forever](https://www.panopticons.uk.net/)) |
| http://neverssl.com/ | `curl -L http://neverssl.com/` | 리다이렉트(랜덤 서브도메인) 추적 | SSL·HSTS·HTTP/2 없이 평문만 ([NeverSSL 원문](https://gist.github.com/markcwebster/9bdf30655cdd5279bad13993ac87c85d)), 랜덤 서브도메인으로 이동 ([scan 보고서](https://scanmalware.com/result/a004e352-ad8c-4ada-b784-4df4d750d1fb)) |
| http://info.cern.ch/ | `curl http://info.cern.ch/hypertext/WWW/TheProject.html` | 최초 웹사이트, 단순 HTML | 세계 최초 웹사이트 주소 ([CERN](https://home.cern/science/computing/the-birth-of-the-web/short-history-web/)) |
| http://http.rip/ | `curl http://http.rip/` | 평문 HTTP 확인용 | HTTP 테스트용으로 쓴다는 사용자 댓글 ([HN 댓글](https://frontpage-app.vercel.app/newest/45736499)) — 확인 필요 |
| http://perdu.com/ | `curl http://perdu.com/` | 아주 작은 응답 | 평문 테스트용으로 쓴다는 사용자 댓글 ([HN 댓글](https://frontpage-app.vercel.app/newest/45736499)) — 확인 필요 |

### 4-2. HTTP/1.x — 연결 확인(captive portal 탐지) URL (응답이 작고 고정됨)

| URL | 기대 응답 | 확인 목적 | 근거 |
|---|---|---|---|
| http://detectportal.firefox.com/success.txt | 200 | 고정 응답 | [scivision gist](https://gist.github.com/scivision/6d985750f9a238171ef2c141e1c83a4c) |
| http://www.msftconnecttest.com/connecttest.txt | 200 | Windows 연결 확인 URL | [SANS ISC](https://isc.sans.edu/diary.html?date=2026-07-21) |
| http://captive.apple.com/hotspot-detect.html | 200, "Success" | Apple 연결 확인 URL | [SANS ISC](https://isc.sans.edu/diary.html?date=2026-07-21) |
| http://connectivitycheck.gstatic.com/generate_204 | **204 No Content** | 본문 없는 응답(204) 처리 확인 | [scivision gist](https://gist.github.com/scivision/6d985750f9a238171ef2c141e1c83a4c) |
| http://connectivity-check.ubuntu.com/generate_204 | 204 | Ubuntu 연결 확인 URL | [scivision gist](https://gist.github.com/scivision/6d985750f9a238171ef2c141e1c83a4c) |

### 4-3. HTTP/1.x — API·에코 서버 (메서드·헤더·상태 코드 다양하게)

| URL | curl 예시 | 확인 목적 | 근거 |
|---|---|---|---|
| http://httpbin.org/redirect/2 | `curl -L http://httpbin.org/redirect/2` | 302 리다이렉트 연속 | [httpbin 엔드포인트](https://github.com/josher19/httpbin) |
| http://httpbin.org/cookies | `curl -b "session=tok0001" http://httpbin.org/cookies` | Cookie 헤더 | [httpbin 엔드포인트](https://github.com/josher19/httpbin) |
| http://httpbin.org/response-headers?key=val | `curl "http://httpbin.org/response-headers?x-test=hello"` | 원하는 응답 헤더 | [httpbin 엔드포인트](https://github.com/josher19/httpbin) |
| http://httpbin.org/status/500 | `curl http://httpbin.org/status/500` | 5xx 상태 코드 | [httpbin 엔드포인트](https://github.com/kingslef/httpbin) |
| http://httpbin.org/html | `curl http://httpbin.org/html` | HTML 본문 | [httpbin 엔드포인트](https://github.com/josher19/httpbin) |
| PUT·DELETE | `curl -X PUT -d "a=1" http://httpbin.org/put`, `curl -X DELETE http://httpbin.org/delete` | 다른 메서드 | [httpbin 엔드포인트](https://github.com/kingslef/httpbin) |
| http://postman-echo.com/get | `curl "http://postman-echo.com/get?foo=bar"` | httpbin 대체 에코 서버 | 로컬 테스트용 HTTP 버전 `http://postman-echo.com` 안내 ([Postman Echo API](https://matrix-db-api-directory.pages.dev/api/postman-echo)) — 확인 필요 |
| http://postman-echo.com/post | `curl -d "id=student&pw=1234" http://postman-echo.com/post` | POST | 위와 같음 |

### 4-4. keep-alive (연결 하나에 요청 여러 개)

| curl 예시 | 확인 목적 |
|---|---|
| `curl http://example.com/ http://example.com/` | 연결 #1 하나에 요청·응답 2쌍 |
| `curl http://httpbin.org/get http://httpbin.org/status/404` | 같은 연결에서 200 → 404 |

### 4-5. HTTP/2 (평문 h2c)

평문 HTTP/2를 받는 공개 서버는 드물어서 nghttp2.org 안의 경로를 다양하게 쓴다 ([nghttp2 README](https://git.walkero.gr/walkero/nghttp2/src/commit/1d5a1b895b10f22b74ca31d8b882d39a4c2714ef/README.rst), `/httpbin` 메뉴는 1차 캡처 `wsl.pcapng` 본문에서 확인).

| URL | curl 예시 | 확인 목적 |
|---|---|---|
| http://nghttp2.org/httpbin/get | `curl --http2-prior-knowledge http://nghttp2.org/httpbin/get` | HTTP/2 GET |
| http://nghttp2.org/httpbin/post | `curl --http2-prior-knowledge -d "id=student&pw=1234" http://nghttp2.org/httpbin/post` | HTTP/2 POST·DATA 본문 |
| http://nghttp2.org/httpbin/status/404 | `curl --http2-prior-knowledge http://nghttp2.org/httpbin/status/404` | HTTP/2 상태 코드 404 |
| http://nghttp2.org/httpbin/headers | `curl --http2-prior-knowledge -H "X-Test: hello" http://nghttp2.org/httpbin/headers` | 사용자 헤더 HPACK 인코딩 (경로 확인 필요) |
| 여러 경로 한 번에 | `curl --http2-prior-knowledge http://nghttp2.org/httpbin/get http://nghttp2.org/httpbin/headers` | 한 연결에 stream 1·3, **HPACK 동적 테이블** 재사용 |

---

## 한계
- IPv4만 지원, TCP 순서 뒤바뀜은 재정렬하지 않고 gap 경고 후 계속 분석
- HTTPS(TLS), HTTP/3(QUIC)는 범위 밖
- SETTINGS 8·9번 등 최신 설정 ID는 이름 대신 `?(번호)`로 표시
