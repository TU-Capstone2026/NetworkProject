"""bt_sniffer 결과 txt 에서 캡처한 사람의 공인 IP 를 xxx.xxx.xxx.xxx 로 가린다.

공인 IP 는 상대가 알려 준 "내 주소" 필드에서 찾는다.
  - DHT 응답의 ip 필드         : ip (상대가 본 내 주소): 1.2.3.4:5678
  - 확장 핸드셰이크의 yourip   : yourip (상대가 본 내 IP): 1.2.3.4
여기서 찾은 공인 IP 가 파일 어디에 나오든 모두 가린다. 사설·루프백 주소는 그대로 둔다.
줄 수는 바뀌지 않으므로 줄 번호로 가리키는 자료(report_tip.md 등)는 그대로 쓸 수 있다.

사용법
  python3 scripts/mask_ip.py captures/result_real.txt              (같은 파일에 덮어씀)
  python3 scripts/mask_ip.py 원본.txt -o 가린결과.txt
  python3 scripts/mask_ip.py 원본.txt --ip 203.0.113.7              (가릴 IP 를 직접 추가)
"""
import argparse
import re
import sys

MASK = "xxx.xxx.xxx.xxx"
FIELD = re.compile(r"상대가 본 내 (?:주소|IP)\): (\d{1,3}(?:\.\d{1,3}){3})")
PRIVATE = re.compile(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.)")


def find_public_ips(text):
    return sorted({ip for ip in FIELD.findall(text) if not PRIVATE.match(ip)})


def mask_text(text, extra=()):
    ips = set(find_public_ips(text)) | set(extra)
    count = 0
    for ip in sorted(ips, key=len, reverse=True):
        # 다른 IP 의 일부(예: 1.2.3.4 와 11.2.3.45)가 바뀌지 않도록 숫자 경계를 확인
        pat = re.compile(r"(?<![\d.])" + re.escape(ip) + r"(?![\d])")
        text, n = pat.subn(MASK, text)
        count += n
    return text, ips, count


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="bt_sniffer 결과에서 내 공인 IP 가리기")
    ap.add_argument("input")
    ap.add_argument("-o", "--output", help="저장할 파일 (생략하면 입력 파일에 덮어씀)")
    ap.add_argument("--ip", action="append", default=[], help="추가로 가릴 IP (여러 번 지정 가능)")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as f:
        text = f.read()
    masked, ips, count = mask_text(text, args.ip)
    out = args.output or args.input
    with open(out, "w", encoding="utf-8", newline="") as f:
        f.write(masked)
    print(f"{out}: 공인 IP {len(ips)}개, {count}곳을 {MASK} 로 가림 (줄 수 {len(text.splitlines())} 그대로)")


if __name__ == "__main__":
    main()
