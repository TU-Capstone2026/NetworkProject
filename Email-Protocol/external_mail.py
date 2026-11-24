"""External test mail. Secrets are prompted locally and stay in memory."""
import argparse
from email import policy
from email.parser import BytesParser
from getpass import getpass
import imaplib
import poplib
import re
import smtplib
import ssl
import sys
import time


def options(sending):
    parser = argparse.ArgumentParser()
    parser.add_argument("--external", action="store_true")
    parser.add_argument("--account", required=True)
    parser.add_argument("--host", help="mail server DNS name")
    parser.add_argument("--oauth", action="store_true", help="prompt for an issued OAuth access token")
    if sending:
        parser.add_argument("--to", help="defaults to your account")
    else:
        parser.add_argument("--id", required=True, help="Message-ID printed by sender, including angle brackets")
        parser.add_argument("--pop", action="store_true", help="use POP3 instead of IMAP")
    return parser.parse_args()


def credentials(args):
    secret = getpass("OAuth access token: " if args.oauth else "앱 비밀번호: ")
    if args.oauth:
        return f"user={args.account}\x01auth=Bearer {secret}\x01\x01".encode()
    return secret


def send(make_mail):
    args = options(True)
    secret = credentials(args)
    context = ssl.create_default_context()
    for line in sys.stdin:
        msg = make_mail(line.rstrip("\n"))
        msg.replace_header("From", args.account)
        msg.replace_header("To", args.to or args.account)
        msg.replace_header("Subject", "Network project mail test")
        with smtplib.SMTP(args.host or "smtp.gmail.com", 587, timeout=20) as client:
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
            if args.oauth:
                client.auth("XOAUTH2", lambda challenge=None: secret.decode() if challenge is None else "")
            else:
                client.login(args.account, secret)
            client.send_message(msg)
        print(f"SMTP 접수 완료  {msg['Message-ID']}", flush=True)


def imap_read(args, secret):
    with imaplib.IMAP4_SSL(args.host or "imap.gmail.com", 993,
                           ssl_context=ssl.create_default_context(), timeout=20) as client:
        if args.oauth:
            client.authenticate("XOAUTH2", lambda challenge: secret if not challenge else b"")
        else:
            client.login(args.account, secret)
        if client.select("INBOX", readonly=True)[0] != "OK":
            raise RuntimeError("INBOX 열기 실패")
        for attempt in range(12):
            status, data = client.uid("SEARCH", None, "HEADER", "Message-ID", '"' + args.id + '"')
            if status != "OK":
                raise RuntimeError("Message-ID 검색 실패")
            for uid in reversed(data[0].split()):
                status, rows = client.uid("FETCH", uid, "(BODY.PEEK[])")
                if status == "OK":
                    for row in rows:
                        if isinstance(row, tuple):
                            msg = BytesParser(policy=policy.default).parsebytes(row[1])
                            if str(msg["Message-ID"]) == args.id:
                                return msg
            if attempt < 11:
                time.sleep(3)
    raise RuntimeError("INBOX에서 지정한 메일을 찾지 못했어.")


def pop_read(args, secret):
    client = poplib.POP3_SSL(args.host or "pop.gmail.com", 995,
                             context=ssl.create_default_context(), timeout=20)
    try:
        if args.oauth:
            raise RuntimeError("POP3 테스트는 앱 비밀번호를 사용해. OAuth 수신은 IMAP을 사용해.")
        client.user(args.account)
        client.pass_(secret)
        count, _ = client.stat()
        parser = BytesParser(policy=policy.default)
        for number in range(count, max(0, count - 30), -1):
            header = b"\r\n".join(client.top(number, 0)[1])
            if str(parser.parsebytes(header)["Message-ID"]) == args.id:
                return parser.parsebytes(b"\r\n".join(client.retr(number)[1]))
        raise RuntimeError("POP으로 제공된 최근 30통에서 해당 메일을 찾지 못했어.")
    finally:
        client.quit()


def receive():
    args = options(False)
    if not re.fullmatch(r"<[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+>", args.id):
        raise ValueError("송신 터미널에 표시된 <Message-ID>를 그대로 입력해.")
    secret = credentials(args)
    msg = pop_read(args, secret) if args.pop else imap_read(args, secret)
    part = msg.get_body(preferencelist=("plain",))
    if part is None:
        raise RuntimeError("텍스트 본문이 없어.")
    print(part.get_content().rstrip("\r\n"))
