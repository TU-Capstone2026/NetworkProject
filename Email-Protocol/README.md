# 로컬 메일 패킷 실습

같은 컴퓨터에서 세 터미널을 열고 각각 이 폴더로 이동한다. 이전 데모 서버가 실행 중이면 먼저 종료한다. C 컴파일러와 make, Python 3.9 이상이 필요하며 GUI에는 Tkinter가 필요하다. Ubuntu Server처럼 화면이 없는 환경에서는 Mac에서 GUI를 실행하고 캡처 출력을 SSH로 전달할 수 있다.

먼저 한 번만 `make`를 실행한다.

| 터미널 | macOS | Ubuntu 데스크톱 |
|---|---|---|
| 1 · 수신 | `python3 receiver.py` | `python3 receiver.py` |
| 2 · 캡처 GUI | `sudo ./mail_capture lo0 \| python3 capture_gui.py` | `sudo ./mail_capture lo \| python3 capture_gui.py` |
| 3 · 송신 | `python3 sender.py` | `python3 sender.py` |

송신 터미널에 문장을 입력하고 Enter를 누른다. 수신 터미널은 시작 후 조용히 기다리다가 수신한 본문을 한 번 출력한다. 송신은 SMTP, 조회는 POP3와 IMAP으로 진행한다. 조회한 두 원문을 비교하고 MIME을 디코딩해서 한글을 복원한다. 각 메일의 헤더와 인코딩된 본문을 합한 크기는 8 KiB 미만이어야 한다. 메일은 메모리에만 보관한다.

GUI의 행 하나는 실제 IPv4/TCP 패킷 하나다. 행을 클릭하면 그 패킷에서 완성된 프로토콜 줄을 아래에서 볼 수 있다. SYN이나 ACK만 있는 행에는 본문이 없다. 시간은 GUI가 캡처 출력을 받은 시각이다. 최근 3,000개 행을 보관한다. 캡처 종료는 두 번째 터미널에서 Ctrl+C를 누른다.

Linux에서는 AF_PACKET/SOCK_RAW, macOS에서는 libpcap으로 인터페이스를 읽는다. 로컬 송수신 포트는 SMTP 2525, POP3 11110, IMAP 11430이다. 기존 캡처기의 표준 평문 포트도 지원한다. 프로토콜 분류는 포트 기준이다.

## 외부 메일 테스트

이 업데이트의 파일을 기존 Email-Protocol 폴더에 복사하고 make를 실행한다. 외부 테스트는 로컬 mail_server 없이 실행한다. macOS에서 기본 네트워크 인터페이스를 확인하고 VPN 등 별도 경로가 있으면 실제 메일 서버로 향하는 인터페이스를 선택한다.

```sh
make
route -n get default | awk '/interface:/{print $2}'
sudo ./mail_capture en0 | python3 capture_gui.py
```

다른 터미널에서 실행한다. 아래 주소는 자신의 계정으로 바꾼다. 기본 수신자는 같은 계정이며 --to 로 변경할 수 있다. 앱 비밀번호를 터미널의 숨김 입력창에 입력한다. 계정이 앱 비밀번호를 지원하지 않으면 --oauth 로 이미 발급된 메일 접근용 OAuth 액세스 토큰을 입력한다. 자동 토큰 발급은 포함하지 않는다.

```sh
python3 sender.py --external --account you@gmail.com
python3 receiver.py --external --account you@gmail.com --id '<송신 화면의 Message-ID>'
```

송신 창에 한 줄 입력 후 Enter를 누른다. SMTP가 접수하면 Message-ID가 출력된다. 수신 프로그램은 읽기 전용 INBOX에서 해당 ID를 약 33초간 조회한다. POP3가 활성화된 계정에서는 수신 명령에 --pop 을 붙여 최근 30통의 POP 헤더에서 같은 메일을 찾을 수 있다. POP3는 TOP 지원 및 앱 비밀번호가 필요하다. Gmail이 POP에 공개하는 메시지는 계정 설정에 따라 다를 수 있다.

학교 서버는 각 명령에 --host 를 붙여 학교가 안내한 호스트를 지정한다. 현재 외부 클라이언트 포트는 SMTP STARTTLS 587, IMAPS 993, POP3S 995이다. 캡처기는 SMTPS 465도 분류한다. IP/TCP 헤더와 평문 STARTTLS 협상은 관찰할 수 있고 TLS 구간은 전송 크기와 방향을 표시한다. 캡처를 연결 시작 전에 실행한다. IPv6는 확장 헤더 없이 TCP가 바로 이어지는 패킷을 지원한다.
