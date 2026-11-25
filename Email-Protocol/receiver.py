import imaplib
import poplib
import subprocess
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

def retrieve():
    pop = poplib.POP3("127.0.0.1", 11110, timeout=10)
    try:
        pop.user("demo")
        pop.pass_("demo")
        pop_message = b"\r\n".join(pop.retr(1)[1]) + b"\r\n"
    finally:
        pop.quit()
    with imaplib.IMAP4("127.0.0.1", 11430, timeout=10) as client:
        client.login("demo", "demo")
        if client.select("INBOX", readonly=True)[0] != "OK":
            raise RuntimeError("INBOX 선택 실패")
        status, data = client.fetch("1", "(BODY.PEEK[])")
        if status != "OK" or not data or not isinstance(data[0], tuple):
            raise RuntimeError("IMAP 조회 실패")
        imap_message = data[0][1]
    if imap_message != pop_message:
        raise RuntimeError("POP3와 IMAP 조회 결과가 일치하지 않습니다.")
    return BytesParser(policy=policy.default).parsebytes(imap_message).get_content().rstrip("\r\n")

def main():
    binary = Path(__file__).resolve().with_name("mail_server")
    with subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as server:
        try:
            if server.stdout.readline() != b"READY\n":
                raise RuntimeError("메일 서버를 시작하지 못했습니다. 포트가 이미 사용 중인지 확인하세요.")
            for event in server.stdout:
                if event == b"STORED\n":
                    print(retrieve(), flush=True)
                    server.stdin.write(b"+")
                    server.stdin.flush()
            raise RuntimeError("메일 서버가 종료되었습니다.")
        finally:
            server.terminate()

if __name__ == "__main__":
    try:
        if "--external" in sys.argv:
            import external_mail
            external_mail.receive()
        else:
            main()
    except KeyboardInterrupt:
        pass
    except (RuntimeError, OSError, imaplib.IMAP4.error, poplib.error_proto) as error:
        sys.exit(str(error))
