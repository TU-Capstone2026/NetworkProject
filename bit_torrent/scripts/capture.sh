#!/bin/bash
# bt_sniffer 캡처 자동 실행 - README 4-1(루프백 테스트) / 4-2(실제 토렌트, aria2c)
#
# 사용법 (bit_torrent 폴더에서, make 로 빌드한 뒤)
#   sudo bash scripts/capture.sh lo                 루프백 테스트만
#   sudo bash scripts/capture.sh real [토렌트파일]  실제 토렌트만
#   sudo bash scripts/capture.sh all  [토렌트파일]  둘 다
#
# 토렌트 파일을 주지 않으면 DL_DIR 에 있는 Debian netinst 토렌트를 쓰고,
# 없으면 Debian 공식 사이트에서 최신 netinst 토렌트를 받아 SHA256SUMS 로 확인합니다.
#
# 환경 변수 (sudo 뒤에 붙임. 예: sudo DURATION=60 bash scripts/capture.sh real)
#   OUT       결과 폴더. 기본값 captures/run_<날짜_시각> (기존 결과를 덮어쓰지 않음)
#   IFACE     실제 토렌트를 캡처할 인터페이스. 기본값 eth0 (WSL2)
#   DURATION  aria2c 실행 시간(초). 기본값 120
#   DL_DIR    토렌트를 받을 폴더. 기본값 ~/bt_download (레포 밖. ISO 가 약 758MB 공간을 미리 차지)
#
# 결과 (OUT 폴더)
#   bt_lo.pcap, result_lo.txt        루프백 패킷 원본 / 분석 결과
#   bt_real.pcap, result_real.txt    실제 토렌트 패킷 원본 / 분석 결과 (result_real.txt 는 내 공인 IP 를 가린 것)
#   aria2c.log                       aria2c 실행 기록
# 공인 IP 를 가리기 전 원본 result_real.txt 는 /tmp 의 작업 폴더에만 남깁니다.

set -u

MODE="${1:-}"
TORRENT_ARG="${2:-}"
case "$MODE" in
  lo|real|all) ;;
  *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "Raw Socket 과 tcpdump 에 root 권한이 필요합니다: sudo bash $0 $*"; exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IFACE="${IFACE:-eth0}"
DURATION="${DURATION:-120}"

# 테스트 생성기·aria2c 는 일반 사용자로 실행 (README: sudo 필요 없음)
RUN_USER="${SUDO_USER:-}"
[ -n "$RUN_USER" ] && [ "$RUN_USER" != "root" ] || RUN_USER="$(stat -c %U "$BT_DIR")"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
DL_DIR="${DL_DIR:-$RUN_HOME/bt_download}"
OUT="${OUT:-$BT_DIR/captures/run_$(date +%Y%m%d_%H%M%S)}"
STAGE="$(mktemp -d /tmp/bt_capture.XXXXXX)"

as_user() {
  if [ "$RUN_USER" = "root" ]; then "$@"; return; fi
  setpriv --reuid="$RUN_USER" --regid="$(id -g "$RUN_USER")" --init-groups env HOME="$RUN_HOME" "$@"
}
step() { echo; echo "==================== $* ===================="; date '+%H:%M:%S'; }
die()  { echo "오류: $*"; exit 1; }

TD=""; SN=""; SJ=""
stop_capture() {   # 분석기에 SIGINT(Ctrl+C 와 같음) → 통계 출력 후 종료, 그다음 tcpdump 종료
  [ -n "$SN" ] && kill -INT "$SN" 2>/dev/null
  [ -n "$SJ" ] && wait "$SJ" 2>/dev/null
  sleep 1
  [ -n "$TD" ] && kill -TERM "$TD" 2>/dev/null && wait "$TD" 2>/dev/null
  TD=""; SN=""; SJ=""
}
trap 'echo; echo "중단 요청 - 지금까지 캡처한 내용을 정리합니다"' INT

start_capture() {  # $1=인터페이스  $2=pcap  $3=결과 txt  $4=분석기 옵션  $5=화면 출력(yes/no)
  tcpdump -i "$1" -Z root -B 16384 -U -w "$2" 2>"$2.log" &
  TD=$!
  sleep 1
  if [ "$5" = "yes" ]; then
    ( "$BT_DIR/bt_sniffer" -i "$1" $4 | tee -i "$3" ) &
  else
    ( "$BT_DIR/bt_sniffer" -i "$1" $4 | tee -i "$3" >/dev/null ) &
  fi
  SJ=$!
  sleep 1
  SN="$(pgrep -nx bt_sniffer)"
  [ -n "$SN" ] || { kill -TERM "$TD"; die "bt_sniffer 를 시작하지 못했습니다"; }
}

# ---------------------------------------------------------------- 사전 확인
[ -x "$BT_DIR/bt_sniffer" ] && [ -x "$BT_DIR/test/bt_testgen" ] || die "먼저 bit_torrent 폴더에서 make 로 빌드하세요"
command -v tcpdump >/dev/null || die "tcpdump 가 없습니다: sudo apt install -y tcpdump"
if [ "$MODE" != "lo" ]; then
  command -v aria2c >/dev/null || die "aria2c 가 없습니다: sudo apt install -y aria2"
  ip link show "$IFACE" >/dev/null 2>&1 || die "인터페이스 $IFACE 가 없습니다 (ip -br a 로 확인 후 IFACE=이름)"
fi
for p in bt_sniffer tcpdump aria2c; do
  pgrep -x "$p" >/dev/null && die "이미 실행 중인 $p 가 있습니다. 종료한 뒤 다시 실행하세요"
done
mkdir -p "$OUT" || die "결과 폴더를 만들 수 없습니다: $OUT"
echo "결과 폴더: $OUT"
echo "일반 사용자: $RUN_USER"

# ---------------------------------------------------------------- 4-1 루프백
run_lo() {
  step "루프백 테스트 (lo)"
  start_capture lo "$OUT/bt_lo.pcap" "$OUT/result_lo.txt" "-d" yes
  ( cd "$BT_DIR" && as_user ./test/bt_testgen )
  sleep 2
  stop_capture
  echo "--- tcpdump ---"; grep -E "captured|dropped" "$OUT/bt_lo.pcap.log"; rm -f "$OUT/bt_lo.pcap.log"
}

# ---------------------------------------------------------------- 토렌트 파일 준비
find_torrent() {
  if [ -n "$TORRENT_ARG" ]; then
    [ -f "$TORRENT_ARG" ] || die "토렌트 파일이 없습니다: $TORRENT_ARG"
    TORRENT="$(cd "$(dirname "$TORRENT_ARG")" && pwd)/$(basename "$TORRENT_ARG")"; return
  fi
  as_user mkdir -p "$DL_DIR"
  TORRENT="$(ls -t "$DL_DIR"/debian-*-amd64-netinst.iso.torrent 2>/dev/null | head -1)"
  [ -n "$TORRENT" ] && return
  local base="https://cdimage.debian.org/debian-cd/current/amd64/bt-cd/" name
  name="$(as_user curl -fsSL "$base" | grep -o 'debian-[0-9.]*-amd64-netinst\.iso\.torrent' | head -1)"
  [ -n "$name" ] || die "Debian netinst 토렌트 이름을 찾지 못했습니다. 직접 받아서 경로를 넘겨 주세요"
  echo "토렌트 받기: $base$name"
  ( cd "$DL_DIR" && as_user curl -fsSL -o "$name" "$base$name" ) || die "토렌트 다운로드 실패"
  ( cd "$DL_DIR" && as_user curl -fsSL "${base}SHA256SUMS" | grep " $name\$" | sha256sum -c - ) || die "SHA256SUMS 확인 실패"
  TORRENT="$DL_DIR/$name"
}

# ---------------------------------------------------------------- 4-2 실제 토렌트
run_real() {
  find_torrent
  local dir iso
  dir="$(dirname "$TORRENT")"; iso="$dir/$(basename "$TORRENT" .torrent)"
  [ -e "$iso.aria2" ] && echo "주의: $iso.aria2 가 남아 있어 이어받기가 됩니다. 이미 받은 조각은 다시 받지 않아 트래픽이 달라집니다."

  step "실제 토렌트 ($IFACE, aria2c ${DURATION}초)"
  echo "토렌트: $TORRENT"
  # 대용량이라 WSL 내부 디스크(/tmp)에 먼저 기록한 뒤 OUT 으로 복사
  start_capture "$IFACE" "$STAGE/bt_real.pcap" "$STAGE/result_real.txt" "-p 6881" no
  ( while sleep 15; do
      printf '[진행] %s  분석 결과 %s줄, pcap %s\n' "$(date +%H:%M:%S)" \
        "$(wc -l < "$STAGE/result_real.txt")" "$(du -h "$STAGE/bt_real.pcap" | cut -f1)"
    done ) &
  local pj=$!

  # README 4-2 방법 A 와 같은 옵션. DURATION 초 뒤 SIGINT(Ctrl+C)로 정상 종료, 30초 안에 안 끝나면 강제 종료
  ( cd "$dir" && timeout --foreground -s INT -k 30 "$DURATION" \
      setpriv --reuid="$RUN_USER" --regid="$(id -g "$RUN_USER")" --init-groups env HOME="$RUN_HOME" \
      aria2c --listen-port=6881 --dht-listen-port=6881 --disable-ipv6=true \
             --bt-require-crypto=false --seed-time=0 "$TORRENT" ) > "$OUT/aria2c.log" 2>&1
  echo "aria2c 종료 (124 = 시간이 다 되어 중지): $?"
  sleep 5                        # 종료 직후의 FIN/ACK/RST 까지 캡처
  kill "$pj" 2>/dev/null; wait "$pj" 2>/dev/null
  stop_capture
  echo "--- tcpdump ---"; grep -E "captured|dropped" "$STAGE/bt_real.pcap.log"

  echo "결과 복사 중..."
  cp "$STAGE/bt_real.pcap" "$OUT/bt_real.pcap"
  if command -v python3 >/dev/null; then
    python3 -I "$SCRIPT_DIR/mask_ip.py" "$STAGE/result_real.txt" -o "$OUT/result_real.txt"
  else
    cp "$STAGE/result_real.txt" "$OUT/result_real.txt"
    echo "주의: python3 가 없어 공인 IP 를 가리지 못했습니다. 올리기 전에 scripts/mask_ip.py 로 가리세요."
  fi
  echo "공인 IP 를 가리기 전 원본: $STAGE/result_real.txt"
  echo "받다 만 파일이 남아 있습니다. 필요 없으면 지우세요: rm -i \"$iso\" \"$iso.aria2\""
}

[ "$MODE" = "real" ] || run_lo
[ "$MODE" = "lo" ]   || run_real

step "완료"
rmdir "$STAGE" 2>/dev/null     # 루프백만 했으면 빈 작업 폴더 정리 (실제 토렌트 원본이 있으면 남김)
chown -R "$RUN_USER" "$OUT" 2>/dev/null
ls -la "$OUT"
for f in "$OUT"/result_*.txt; do
  [ -f "$f" ] && { echo "--- $(basename "$f") 통계 ---"; sed -n '/캡처 통계/,$p' "$f"; }
done
