import smtplib
import sys
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate, make_msgid

def make_mail(sentence):
    msg = EmailMessage(policy=SMTP)
    msg["From"] = "sender@example.test"
    msg["To"] = "receiver@example.test"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="example.test")
    msg["Subject"] = "Local message"
    msg.set_content(sentence, charset="utf-8", cte="base64")
    return msg

def main():
    for line in sys.stdin:
        msg = make_mail(line.rstrip("\n"))
        if len(msg.as_bytes()) >= 8192:
            print("문장이 로컬 메일함의 8 KiB 한도를 넘어.", file=sys.stderr)
            continue
        try:
            with smtplib.SMTP("127.0.0.1", 2525, timeout=10) as client:
                client.send_message(msg)
        except (OSError, smtplib.SMTPException) as error:
            print(f"전송 실패 — {error}", file=sys.stderr)

if __name__ == "__main__":
    try:
        if "--external" in sys.argv:
            import external_mail
            external_mail.send(make_mail)
        else:
            main()
    except KeyboardInterrupt:
        pass
