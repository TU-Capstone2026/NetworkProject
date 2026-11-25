"""bt_sniffer 결과 txt 의 일부 줄을 터미널 모양 PNG 로 그린다 (보고서용).

- 제목줄에 파일 이름, 줄 번호, 설명을 넣고 왼쪽에 원본 줄 번호를 표시한다.
- 떨어진 구간은 한 장에 이어 붙이고 사이에 "(중략)" 줄을 넣는다.
- 영문은 고정폭 글꼴, 한글은 2칸 폭으로 맞춰 터미널과 같은 열로 정렬한다.
- 캡처한 사람의 공인 IP 는 mask_ip.py 와 같은 규칙으로 xxx.xxx.xxx.xxx 로 가린다.
- 필요한 것: Python 3, Pillow (pip install pillow)

사용법 (bit_torrent 폴더에서)
  python scripts/render_png.py --preset 20261125
      captures/result_*.txt 로 captures/png/ 의 21장을 다시 만든다
  python scripts/render_png.py captures/result_real.txt 29-42 -t "3-way handshake + 핸드셰이크" -o out.png
  python scripts/render_png.py captures/result_real.txt 251-254 566-585 -t "interested → unchoke → request" -o out.png

글꼴은 Windows 의 Consolas·맑은 고딕을 먼저 찾고(Windows, WSL 의 /mnt/c 모두),
없으면 리눅스의 DejaVu Sans Mono·Noto Sans CJK·나눔고딕코딩을 찾는다.
직접 지정하려면 --mono-font, --kor-font 를 쓴다.
"""
import argparse
import os
import re
import sys
import unicodedata

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mask_ip import mask_text  # noqa: E402

BT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MONO_CANDIDATES = [
    r"C:\Windows\Fonts\consola.ttf", "/mnt/c/Windows/Fonts/consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]
KOR_CANDIDATES = [
    r"C:\Windows\Fonts\malgun.ttf", "/mnt/c/Windows/Fonts/malgun.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/nanum/NanumGothicCoding.ttf",
]

S = 2                       # 2배 해상도 (인쇄용)
SIZE = 14 * S
LINE_H = int(SIZE * 1.45)
PAD = 18 * S
TITLE_H = 30 * S

BG, TITLE_BG, FG, DIM, GUTTER = "#1e1e1e", "#2d2d30", "#d4d4d4", "#5f6368", "#6e7681"
COLORS = [
    (re.compile(r"^-{20,}$"), DIM),
    (re.compile(r"^#\d+ \[.*$"), "#dcdcaa"),
    (re.compile(r"^#\d+ \[[^\]]+\] (?P<c>\[송신\])"), "#4fc1ff"),
    (re.compile(r"^#\d+ \[[^\]]+\] (?P<c>\[수신\])"), "#89d185"),
    (re.compile(r"^ \[(IP |TCP|UDP)\]"), "#9cdcfe"),
    (re.compile(r"^ \[APP\]"), "#c586c0"),
    (re.compile(r"\[TCP 연결 (설정|해제)\]"), "#ce9178"),
    (re.compile(r"Flags=\[[A-Z,]+\]"), "#d7ba7d"),
    (re.compile(r"^=+ 캡처 통계 =+$|^-+ BitTorrent 분석 통계 -+$"), "#dcdcaa"),
    (re.compile(r"xxx\.xxx\.xxx\.xxx"), "#f48771"),
]

LO, REAL = "result_lo.txt", "result_real.txt"
# 2026-11-25 캡처 (captures/) 의 보고서용 구간. 줄 번호는 이 캡처 파일에만 해당한다.
PRESET_20261125 = [
    (LO, "lo_01_handshake", "3-way handshake + 핸드셰이크(송신)", [(3, 16)]),
    (LO, "lo_02_handshake_reply", "상대 핸드셰이크 + bitfield + 확장 핸드셰이크", [(18, 39)]),
    (LO, "lo_03_interested_request", "interested → unchoke → request", [(41, 55)]),
    (LO, "lo_04_piece", "piece (여러 세그먼트로 나뉨)", [(57, 62)]),
    (LO, "lo_05_fin", "FIN 연결 해제 4단계", [(105, 123)]),
    (LO, "lo_06_http_tracker", "HTTP 트래커 요청/응답", [(125, 148)]),
    (LO, "lo_07_udp_tracker", "UDP 트래커 connect → announce → scrape → error", [(150, 216)]),
    (LO, "lo_08_dht", "DHT ping / find_node / get_peers / announce_peer / error", [(218, 298)]),
    (LO, "lo_09_stats", "캡처 통계", [(310, 335)]),
    (REAL, "real_01_http_tracker_started", "HTTP 트래커 announce(started) + 응답", [(3, 27)]),
    (REAL, "real_02_handshake", "3-way handshake + 핸드셰이크(송신)", [(29, 42)]),
    (REAL, "real_03_handshake_reply", "상대 핸드셰이크 + 확장 + bitfield, 내 확장 핸드셰이크 + Port", [(67, 99)]),
    (REAL, "real_04_interested_request", "interested → unchoke → request ×6 (Index=3023)", [(251, 254), (566, 585)]),
    (REAL, "real_05_piece", "piece Index=3023 (세그먼트 경계를 넘어 이어짐)", [(623, 628), (658, 672)]),
    (REAL, "real_06_fin_peer", "FIN: 상대가 먼저 끊음 (FIN → FIN+ACK → RST)", [(2027, 2035), (2053, 2056)]),
    (REAL, "real_07_fin_shutdown", "FIN: aria2c 종료 시 (내 FIN → 상대 ACK → RST)", [(7019, 7022), (7094, 7102)]),
    (REAL, "real_08_http_tracker_stopped", "HTTP 트래커 announce(stopped) + 응답", [(7129, 7171)]),
    (REAL, "real_09_dht_ping", "DHT ping 질의 ↔ 응답 (Transaction ID 일치)", [(59, 65), (166, 173)]),
    (REAL, "real_10_dht_find_node", "DHT find_node 질의 ↔ 응답 (Transaction ID 일치)", [(371, 378), (397, 405)]),
    (REAL, "real_11_dht_get_peers", "DHT get_peers 수신 질의 → 내 응답(token)", [(6735, 6753)]),
    (REAL, "real_12_stats", "캡처 통계", [(7173, 7196)]),
]
PRESETS = {"20261125": PRESET_20261125}


def pick_font(candidates, given, size):
    for path in ([given] if given else candidates):
        if path and os.path.exists(path):
            return ImageFont.truetype(path, size)
    sys.exit("글꼴을 찾지 못했습니다. --mono-font / --kor-font 로 경로를 지정하세요: " + ", ".join(candidates))


class Renderer:
    def __init__(self, mono_path=None, kor_path=None):
        self.mono = pick_font(MONO_CANDIDATES, mono_path, SIZE)
        self.kor = pick_font(KOR_CANDIDATES, kor_path, int(SIZE * 0.92))
        self.kor_title = pick_font(KOR_CANDIDATES, kor_path, int(SIZE * 0.9))
        self.cw = self.mono.getlength("M")      # 한 칸 폭

    @staticmethod
    def cells(ch):
        return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1

    @staticmethod
    def colorize(line):
        cols = [FG] * len(line)
        for rx, color in COLORS:
            for m in rx.finditer(line):
                g = "c" if "c" in rx.groupindex else 0
                for i in range(m.start(g), m.end(g)):
                    cols[i] = color
        return cols

    def render(self, title, rows, out_path):
        """rows: (원본 줄 번호 또는 None, 텍스트)"""
        cw = self.cw
        digits = max(len(str(n)) for n, _ in rows if n is not None)
        gutter_w = (digits + 2) * cw
        max_cells = max(sum(self.cells(c) for c in t) for _, t in rows)
        width = int(max(PAD + gutter_w + max_cells * cw + PAD, self.kor_title.getlength(title) + 2 * PAD))
        height = TITLE_H + PAD + LINE_H * len(rows) + PAD

        img = Image.new("RGB", (width, height), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, width, TITLE_H], fill=TITLE_BG)
        d.text((PAD, TITLE_H // 2), title, font=self.kor_title, fill="#cccccc", anchor="lm")
        d.line([PAD + gutter_w - cw, TITLE_H, PAD + gutter_w - cw, height], fill="#333333", width=S)

        y0 = TITLE_H + PAD
        for r, (no, text) in enumerate(rows):
            base = y0 + r * LINE_H + int(LINE_H * 0.75)
            if no is not None:
                d.text((PAD + digits * cw, base), str(no), font=self.mono, fill=GUTTER, anchor="rs")
            x = PAD + gutter_w
            cols = self.colorize(text) if no is not None else [DIM] * len(text)
            for ch, col in zip(text, cols):
                w = self.cells(ch)
                if ch != " ":
                    if w == 1:
                        d.text((x, base), ch, font=self.mono, fill=col, anchor="ls")
                    else:
                        d.text((x + w * cw / 2, base), ch, font=self.kor, fill=col, anchor="ms")
                x += w * cw
        img.save(out_path, optimize=True)
        return width, height


def load_masked(path):
    with open(path, encoding="utf-8") as f:
        text, _, _ = mask_text(f.read())
    return text.splitlines()


def build_rows(lines, ranges):
    rows = []
    for i, (a, b) in enumerate(ranges):
        if not (1 <= a <= b <= len(lines)):
            sys.exit(f"줄 범위 {a}-{b} 가 파일 범위(1-{len(lines)})를 벗어납니다")
        if i > 0:
            rows.append((None, "      · · ·   (중략)   · · ·"))
        rows.extend((n, lines[n - 1]) for n in range(a, b + 1))
    return rows


def title_of(name, ranges, desc):
    span = ", ".join(f"{a}-{b}" for a, b in ranges)
    return f"{name}  ·  {span}줄  ·  {desc}" if desc else f"{name}  ·  {span}줄"


def parse_range(s):
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", s)
    if not m:
        raise argparse.ArgumentTypeError(f"줄 범위는 29-42 처럼 씁니다: {s}")
    a = int(m.group(1))
    return a, int(m.group(2) or a)


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="bt_sniffer 결과 txt 를 터미널 모양 PNG 로 그리기")
    ap.add_argument("input", nargs="?", help="결과 txt (예: captures/result_real.txt)")
    ap.add_argument("ranges", nargs="*", type=parse_range, help="줄 범위 (예: 29-42 66-99)")
    ap.add_argument("-t", "--title", default="", help="제목줄 설명")
    ap.add_argument("-o", "--output", help="저장할 PNG 경로")
    ap.add_argument("--preset", choices=sorted(PRESETS), help="정해 둔 구간을 한꺼번에 그림")
    ap.add_argument("--captures", default=os.path.join(BT_DIR, "captures"), help="--preset 이 읽을 결과 폴더")
    ap.add_argument("--out-dir", help="--preset 결과 폴더 (기본: <captures>/png)")
    ap.add_argument("--mono-font")
    ap.add_argument("--kor-font")
    args = ap.parse_args()

    rd = Renderer(args.mono_font, args.kor_font)
    if args.preset:
        out_dir = args.out_dir or os.path.join(args.captures, "png")
        os.makedirs(out_dir, exist_ok=True)
        cache = {}
        for name, key, desc, ranges in PRESETS[args.preset]:
            if name not in cache:
                cache[name] = load_masked(os.path.join(args.captures, name))
            out = os.path.join(out_dir, key + ".png")
            w, h = rd.render(title_of(name, ranges, desc), build_rows(cache[name], ranges), out)
            print(f"{out}  {w}x{h}")
        return

    if not args.input or not args.ranges or not args.output:
        ap.error("결과 txt, 줄 범위, -o 출력 경로가 필요합니다 (또는 --preset)")
    lines = load_masked(args.input)
    w, h = rd.render(title_of(os.path.basename(args.input), args.ranges, args.title),
                     build_rows(lines, args.ranges), args.output)
    print(f"{args.output}  {w}x{h}")


if __name__ == "__main__":
    main()
