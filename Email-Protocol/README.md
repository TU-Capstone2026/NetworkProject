# 이메일 패킷 캡처 실습

로컬에서는 평문 SMTP로 메일을 보내고 POP3와 IMAP으로 같은 메일을 조회한다. 외부 실습에서는 Gmail 계정 간에 실제 메일을 발송하고, 수신 계정의 메일을 조회하면서 TLS 구간을 관찰한다.

## 1. 공통 준비

저장소 루트에서 터미널 세 개를 열고 각각 `cd Email-Protocol`로 이동한다. C 컴파일러, `make`, Python 3.9 이상, Tkinter가 필요하다. macOS 빌드는 libpcap을 사용하고, Linux 빌드는 `AF_PACKET/SOCK_RAW`를 사용한다. GUI를 실행하는 컴퓨터에서 Tkinter를 확인한다.

```bash
python3 -c 'import tkinter; print(tkinter.TkVersion)'
make -B
```

빌드는 한 터미널에서 한 번만 하면 된다. `-B`는 기존 실행 파일이 있더라도 현재 소스로 다시 빌드한다. 캡처 명령의 `sudo`에는 컴퓨터 로그인 비밀번호를 입력한다.

## 2. 로컬 평문 실습

| 순서 | 터미널 | 실행 명령 |
|---|---|---|
| 1 | 캡처 GUI | macOS는 `sudo ./mail_capture lo0 \| python3 capture_gui.py`, Linux 데스크톱은 `sudo ./mail_capture lo \| python3 capture_gui.py` |
| 2 | 수신 | `python3 receiver.py` |
| 3 | 송신 | `python3 sender.py` |

GUI가 열리면 송신 터미널에 문장 한 줄을 입력하고 Enter를 누른다. 수신 프로그램이 내부적으로 로컬 메일 서버를 실행하므로, 수신 터미널에서 평소에는 별도 안내 없이 기다린다. 이전 로컬 서버가 포트를 쓰고 있다면 먼저 종료한다.

기대 결과는 수신 터미널의 본문 한 줄과 GUI의 SMTP **2525**, POP3 **11110**, IMAP **11430** 연결이다. 수신 프로그램은 POP3와 IMAP으로 가져온 원문을 대조한 뒤 MIME을 디코딩해서 본문을 한 번 출력한다. 메일은 메모리에 보관하며 헤더와 인코딩된 본문의 합은 8 KiB 미만이다.

## 3. Gmail 외부 송수신 실습

본인 테스트 계정을 사용한다. 이 예시의 `sender@gmail.com`과 `receiver@gmail.com`은 각각 실제 송신·수신 계정으로 바꾼다. 같은 계정으로 시험할 때는 송신 명령의 `--to`를 생략하고 수신 명령에도 같은 주소를 넣는다. 앱 비밀번호는 로그인하는 계정에서 각각 발급해 터미널의 숨김 입력창에만 넣는다. 발급에는 Google 계정의 2단계 인증이 필요하다. [Google 앱 비밀번호 관리](https://myaccount.google.com/apppasswords)

### 터미널 1 · 캡처 GUI

macOS에서는 외부 연결에 사용하는 인터페이스를 확인한다.

```bash
route -n get default | awk '/interface:/{print $2}'
sudo ./mail_capture en0 | python3 capture_gui.py
```

`en0`은 시연에서 사용한 예시다. 네트워크 환경에 맞게 바꾼다. Linux에서는 `ip route show default`의 `dev` 뒤에 표시되는 인터페이스를 사용한다. VPN을 사용한다면 메일 서버로 향하는 실제 인터페이스를 확인한다. GUI가 뜨면 **패킷 비우기**를 누르고 캡처를 켜 둔다.

### 터미널 2 · SMTP로 실제 메일 발송

```bash
python3 sender.py --external --account sender@gmail.com --to receiver@gmail.com
```

`앱 비밀번호:`에 **송신 계정의 앱 비밀번호**만 넣고 Enter를 누른다. 입력한 글자는 화면에 표시되지 않는다. 다음 줄에 보낼 본문만 입력하고 Enter를 누른다. 성공하면 `SMTP 접수 완료 <...>`가 뜬다. **꺾쇠를 포함한 Message-ID 전체**를 복사한다. GUI에는 SMTP **587** 연결이 잡힌다.

### 터미널 3 · IMAP으로 도착한 메일 조회

```bash
python3 receiver.py --external --account receiver@gmail.com --id '<복사한 Message-ID>'
```

작은따옴표 안에 복사한 값을 그대로 넣는다. **수신 계정의 앱 비밀번호**를 입력하면 프로그램이 받은편지함을 읽기 전용으로 열어 해당 ID를 검색한다. 메일이 바로 검색되지 않으면 3초 간격으로 최대 12번 조회한다. 성공하면 본문을 한 번 출력하고 종료하며 GUI에 IMAP **993** 연결이 잡힌다.

POP3도 시험하려면 수신 계정에서 POP을 활성화한 뒤 같은 수신 명령에 `--pop`을 붙인다. 캡처 포트는 **995**다. 수신기는 POP 서버의 `TOP`을 사용해 서버가 제공하는 최근 최대 30통의 헤더를 검사한다. POP 조회 가능 여부는 계정 설정에 따라 달라진다.

학교 서버의 호스트명이 다르면 각 명령에 `--host 서버주소`를 붙인다. 외부 모드의 포트는 SMTP STARTTLS 587, IMAPS 993, POP3S 995로 고정돼 있다. `--oauth`는 이미 발급받은 메일 접근용 OAuth 액세스 토큰을 SMTP 또는 IMAP 인증에 사용한다.

## 4. 캡처 화면에서 확인할 것

- **연결 설정과 종료**는 TCP의 `SYN → SYN ACK → ACK`와 `FIN/ACK`로 확인한다. 행을 선택하면 아래에서 IP 주소, TCP 포트·Seq·Ack·플래그, 응용 계층 요약을 볼 수 있다.
- **로컬 평문**에서는 SMTP `DATA`, POP3 `RETR`, IMAP `FETCH`와 메일 헤더를 응용 계층에서 확인할 수 있다. 명령 줄이 TCP 패킷 여러 개에 걸치면 그 줄이 완성된 행에 표시된다.
- **외부 SMTP**에서는 평문 `EHLO → STARTTLS → 220` 뒤에 TLS 협상이 이어진다. **외부 IMAP·POP3**는 연결 직후 TLS를 시작한다. TLS 구간에서도 방향과 페이로드 길이를 확인할 수 있고, 실제 본문은 인증된 수신 터미널에서 확인한다.
- 메모 앱 등 다른 프로그램도 같은 인터페이스의 메일 포트를 사용할 수 있다. 테스트 직후 새로 나타난 **TCP 연결의 시작 시각, 클라이언트 임시 포트, 서버 포트, SYN 여부**를 함께 본다. **패킷 비우기**는 GUI 기록을 지운다.
- 캡처 종료는 캡처 터미널에서 `Ctrl+C`를 누른다. GUI의 시간은 캡처 출력을 GUI가 받은 시각이다.

## 5. 실행 중 자주 만나는 문제

| 증상 | 확인할 것 |
|---|---|
| `CERTIFICATE_VERIFY_FAILED` | macOS의 Python에서 기본 CA 인증서를 불러오지 못하면, 송신·수신 **각 터미널**에서 `export SSL_CERT_FILE=/etc/ssl/cert.pem`을 실행한 뒤 기존 명령을 다시 실행한다. |
| 외부 모드에서 앱 비밀번호 안내 없이 멈춤 | 현재 디렉터리를 확인하고 `python3 sender.py --external --help` 또는 `python3 receiver.py --external --help`로 외부 모드 옵션이 나오는지 확인한다. |
| 송수신 성공인데 GUI가 0개 | 현재 프로젝트 경로에서 `make -B mail_capture`로 다시 빌드한다. 캡처를 재시작한 뒤 실제 외부 연결의 인터페이스와 `587` 또는 `993` 연결 여부를 확인한다. |
| 수신 터미널에서 메일을 못 찾음 | 수신 계정의 Gmail 받은편지함에서 해당 메일의 **원본 보기**를 열고 `Message-ID`를 대조한다. 꺾쇠를 포함하고 작은따옴표로 감싸서 전달한다. |
