# 테스트 명령 설명

## 0. 스니퍼 실행 명령

```bash
sudo ./http_sniffer eth0 -v 80
```

| 부분 | 의미 |
|---|---|
| `sudo` | 관리자(root) 권한으로 실행 — raw socket은 root 권한이 필요 |
| `./http_sniffer` | 현재 폴더의 스니퍼 실행 파일 |
| `eth0` | 캡처할 네트워크 인터페이스 (WSL의 실제 인터페이스) |
| `-v` | 데이터 없는 ACK까지 출력 → TCP 연결설정(SYN → SYN-ACK → ACK)·해제(FIN → ACK) 과정이 모두 보임 |
| `80` | **80번 포트(HTTP)만** 분석 대상으로 지정 (생략하면 기본값 80·8080·8000) |

- 화면 출력을 파일로도 남기려면 뒤에 `| tee sniff_wsl.log`를 붙인다
- 스니퍼를 **curl보다 먼저** 실행해야 HTTP/2의 HPACK 헤더를 처음부터 해석할 수 있다

---

## 1. 1차 테스트 (2026-11-19)

| 명령 | 의미 | 확인 결과 |
|---|---|---|
| `curl --http1.0 http://httpbin.org/get` | HTTP/1.0으로 GET 요청 | `GET /get HTTP/1.0` → `HTTP/1.0 200 OK` |
| `curl --http1.1 http://httpbin.org/get` | HTTP/1.1로 GET 요청 | `GET /get HTTP/1.1` → `HTTP/1.1 200 OK` |
| `curl -d "id=student&pw=1234" http://httpbin.org/post` | `-d`로 본문을 넣어 POST 요청 | 본문 `id=student&pw=1234`가 평문으로 보임 → `200 OK` |
| `curl http://httpbin.org/status/404` | 404를 돌려주는 주소에 요청 | `HTTP/1.1 404 Not Found` |
| `curl --http2-prior-knowledge http://nghttp2.org/` | 협상 없이 처음부터 HTTP/2(평문 h2c)로 요청 | connection preface, SETTINGS·HEADERS·DATA 프레임, HPACK으로 헤더 복원 (`:status 200` 등) |

## 2. 2차 테스트 (2026-11-20)

| 명령 | 의미 | 확인할 것 |
|---|---|---|
| `curl --http1.0 http://example.com/` | 다른 서버에 HTTP/1.0 요청 | 서버가 달라도 1.0 판별·파싱 |
| `curl --http1.1 http://httpforever.com/` | 응답이 큰 사이트에 HTTP/1.1 요청 | 본문이 여러 세그먼트로 와도 "본문 이어짐 → 완료" |
| `curl http://example.com/ http://example.com/` | URL 2개 → 연결 하나를 재사용(keep-alive) | 한 연결에 요청·응답 2쌍 |
| `curl --http2-prior-knowledge http://nghttp2.org/httpbin/get` | HTTP/2 GET | `:method GET`, `:path /httpbin/get` |
| `curl --http2-prior-knowledge -d "id=student&pw=1234" http://nghttp2.org/httpbin/post` | HTTP/2 POST | DATA 프레임에 본문 평문 |
| `curl --http2-prior-knowledge http://nghttp2.org/httpbin/status/404` | HTTP/2로 404 받기 | `:status 404` |

### curl 옵션

| 옵션 | 의미 |
|---|---|
| `--http1.0` / `--http1.1` | 요청할 HTTP 버전 지정 |
| `--http2-prior-knowledge` | 서버가 HTTP/2를 지원한다고 가정하고 바로 HTTP/2로 시작 |
| `-d "데이터"` | 요청 본문을 넣어 POST로 전송 |

---
출처: [curl 공식 매뉴얼](https://curl.se/docs/manpage.html), `main.c`(인자 처리: `-v`, 포트 번호), 1차 테스트 로그 `HTTP_Test_Result/sniff_wsl.log`
