# HTTP_Test_Result — raw socket 스니퍼 vs Wireshark 비교 분석

같은 시간에 **raw socket 스니퍼(`http_sniffer`)**와 **Wireshark**로 동시에 캡처하고, 같은 패킷끼리 값을 대조한 결과.

| 파일 | 내용 |
|---|---|
| `sniff_wsl.log` / `wsl.pcapng` | 1차 테스트 — 스니퍼 출력 / Wireshark 캡처 |
| `sniff_wsl2.log` / `wsl2.pcapng` | 2차 테스트 — 스니퍼 출력 / Wireshark 캡처 |

## 테스트 환경 (1·2차 공통)
- Windows 11 (25H2) + WSL2 Ubuntu, 같은 PC — 스니퍼: WSL `eth0`(172.23.252.163)에서 `sudo ./http_sniffer eth0 -v`
- Wireshark 4.6.9: `vEthernet (WSL (Hyper-V firewall))`, 캡처 필터 `tcp port 80`, seq·ack 절대값(Relative sequence numbers 해제)
- 요청: curl 8.18.0 / 비교 방법: pcapng를 직접 파싱해 IP·포트·seq·ack·플래그·윈도·TTL·IP ID·길이를 패킷별로 대조

---

## 1차 테스트 비교 분석 (2026-11-19 22:25)

### 요청
| # | curl 명령 | 서버 IP |
|---|---|---|
| 1 | `curl --http1.0 http://httpbin.org/get` | 44.209.237.184 |
| 2 | `curl --http1.1 http://httpbin.org/get` | 44.209.237.184 |
| 3 | `curl -d "id=student&pw=1234" http://httpbin.org/post` | 3.221.253.123 |
| 4 | `curl http://httpbin.org/status/404` | 44.209.237.184 |
| 5 | `curl --http2-prior-knowledge http://nghttp2.org/` | 139.162.123.134 |

### 패킷 대조
| 항목 | 결과 |
|---|---|
| TCP 패킷 수 | 스니퍼 60 = Wireshark 60 |
| IP·포트·seq·ack·플래그·윈도·TTL·IP ID | ✅ **60개 모두 일치** |
| IP 전체 길이 | 59개 일치, 1개 차이 (아래 차이점) |

TCP 연결 설정 예시 (요청 1) — 스니퍼와 Wireshark 값 동일

| 단계 | 방향 | seq / ack / 플래그 |
|---|---|---|
| SYN | 172.23.252.163:41876 → 44.209.237.184:80 | 1896994750 / 0 / SYN |
| SYN-ACK | 44.209.237.184:80 → 172.23.252.163:41876 | 1297739449 / 1896994751 / SYN,ACK |
| ACK | 172.23.252.163:41876 → 44.209.237.184:80 | 1896994751 / 1297739450 / ACK |

### HTTP 해석 대조
| 요청 | 스니퍼 해석 | Wireshark(패킷 원본) | 결과 |
|---|---|---|---|
| 1 | GET `/get` HTTP/1.0 → HTTP/1.0 200 OK (content-length 202) | `GET /get HTTP/1.0` / `HTTP/1.0 200 OK` | ✅ |
| 2 | GET `/get` HTTP/1.1 → HTTP/1.1 200 OK | `GET /get HTTP/1.1` / `HTTP/1.1 200 OK` | ✅ |
| 3 | POST `/post`, Body 18 bytes `id=student&pw=1234` → 200 OK | 같은 시작줄 + 같은 본문 | ✅ |
| 4 | GET `/status/404` → 404 Not Found | `HTTP/1.1 404 Not Found` | ✅ |
| 5 | HTTP/2 preface 감지, 요청 HPACK 6개(`:method GET` `:path /`), 응답 HPACK 14개(`:status 200`, `server nghttpx`…), DATA 6510 bytes를 패킷 3개에서 재조립 | `PRI * HTTP/2.0` + 압축 헤더(28·224 bytes) + HTML 본문 | ✅ (디코딩한 `content-length 6510` = DATA 길이 6510) |

### 차이점
| 패킷 | 스니퍼 | Wireshark | 원인 |
|---|---|---|---|
| nghttp2.org 응답 seq=36167763 | IP total_len 4396 | 0 | 여러 세그먼트가 합쳐진(offload) 패킷을 Windows 쪽은 길이 0으로 기록 — 캡처 위치 차이, 나머지 필드 일치 |

**1차 결론:** 60개 패킷의 IP·TCP 값이 Wireshark와 모두 일치했고, HTTP/1.0·1.1·2의 메서드·URI·상태 코드·헤더를 정확히 해석했다.

---

## 2차 테스트 비교 분석 (2026-11-20 18:02)

### 요청
| # | curl 명령 | 서버 IP |
|---|---|---|
| 1 | `curl --http1.0 http://example.com/` | 104.20.23.154 |
| 2 | `curl --http1.1 http://httpforever.com/` | 104.21.4.210 |
| 3 | `curl http://example.com/ http://example.com/` | 104.20.23.154 |
| 4 | `curl --http2-prior-knowledge http://nghttp2.org/httpbin/get` | 139.162.123.134 |
| 5 | `curl --http2-prior-knowledge -d "id=student&pw=1234" http://nghttp2.org/httpbin/post` | 139.162.123.134 |
| 6 | `curl --http2-prior-knowledge http://nghttp2.org/httpbin/status/404` | 139.162.123.134 |

### 패킷 대조
| 항목 | 결과 |
|---|---|
| TCP 패킷 수 | 스니퍼 87 = Wireshark 87 |
| IP·포트·seq·ack·플래그·윈도·TTL·IP ID | ✅ **87개 모두 일치** |
| IP 전체 길이 | 85개 일치, 2개 차이 (아래 차이점) |
| HTTP 시작줄 | 원본 `GET / HTTP/1.0`, `GET / HTTP/1.1`×3, `HTTP/1.1 200 OK`×4 = 스니퍼 해석 ✅ |

### HTTP 해석 대조
| # | 결과 | 스니퍼 해석 | 새로 검증된 기능 |
|---|---|---|---|
| 1 | ✅ | `GET / HTTP/1.0` → `HTTP/1.1 200 OK`, `Connection: close`, Content-Length 없음 | 연결 종료(FIN)로 본문 끝 판단 (577 bytes) |
| 2 | ✅ | `HTTP/1.1 200 OK`, `Transfer-Encoding: chunked` | 헤더가 세그먼트 2개에 걸침 → 모아서 출력 / chunked 본문이 패킷 4개에 걸쳐 완료 (11,526 bytes) |
| 3 | ✅ | 연결 하나에 요청·응답 2쌍 (각 chunked 589 bytes) | keep-alive |
| 4 | ⚠️ 서버 502 | 요청 HPACK 6개(`:path /httpbin/get`) / 응답 `:status 502` | HTTP/2 요청 경로 디코딩 |
| 5 | ⚠️ 서버 502 | 요청 HPACK 8개(`:method POST`, `content-length 18`) + DATA `id=student&pw=1234` | HTTP/2 POST 본문 평문 확인 |
| 6 | ⚠️ 서버 502 | 요청 `:path /httpbin/status/404` / 응답 `:status 502` | — (404 확인 못 함) |

chunked 바이트 검증: 청크 크기 + 청크 표시 = 스니퍼 누적값
- httpforever.com: `0x2cf9`(11,513) + 13 = **11,526** ✅
- example.com: `0x241`(577) + 12 = **589** ✅ → 스니퍼의 chunked 본문 바이트는 청크 표시를 포함한 전송량

HPACK 근거: 502 응답에서 디코딩한 `content-length: 129` = 실제 DATA 길이 129 ✅

### 차이점
| 패킷 | 스니퍼 | Wireshark | 원인 |
|---|---|---|---|
| httpforever 응답 seq=695202126 | IP total_len 7292 | 0 | 1차와 같은 offload 기록 차이 (payload 7240 등 나머지 일치) |
| httpforever 응답 seq=695209366 | IP total_len 2948 | 0 | 위와 같음 (payload 2896) |
| HTTP/2 요청 4~6 | `:status 502` | 같은 502 응답 | 응답이 `server: nghttpx`의 `502 Bad Gateway` → nghttp2.org 뒤쪽 httpbin 서비스 문제로 보임 (스니퍼 결함 아님), 404는 복구 후 재시도 필요 |

**2차 결론:** 다른 서버에서도 87개 패킷이 Wireshark와 모두 일치했고, FIN으로 끝나는 본문·세그먼트에 걸친 헤더·chunked 본문·keep-alive·HTTP/2 POST를 정상 해석했다.

---

## 종합
| 검증 항목 | 1차 | 2차 |
|---|---|---|
| IP·TCP 헤더 Wireshark 일치 | ✅ 60/60 | ✅ 87/87 |
| 송수신·TCP 연결설정·해제 | ✅ | ✅ |
| HTTP/1.0·1.1 메서드·URI·상태 코드·헤더 | ✅ | ✅ |
| 본문 끝 판단 | Content-Length ✅ | FIN ✅ · chunked ✅ |
| 세그먼트 분할 헤더·keep-alive | — | ✅ |
| HTTP/2 프레임·HPACK | ✅ GET 200 | ✅ GET·POST 요청, 502 응답 |
| HTTP/2 404 | — | ⏳ 서버 502로 재시도 필요 |
