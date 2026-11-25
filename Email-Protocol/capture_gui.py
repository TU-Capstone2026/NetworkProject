"""Run with ./mail_capture INTERFACE | python3 capture_gui.py."""
from packet_details import application_fields, network_fields, tcp_fields
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from queue import Empty, Queue
import re
import sys
from threading import Thread
import tkinter as tk
from tkinter import ttk

PACKET = re.compile(
    r"(SMTP|POP3|IMAP) (\S+) -> (\S+) seq=(\d+) ack=(\d+) flags=(.*?) bytes=(\d+)$"
)
MAIL_PORTS = {"SMTP": {"25", "2525", "465", "587"}, "POP3": {"110", "11110", "995"}, "IMAP": {"143", "11430", "993"}}
MAX_PACKETS = 3000
STAGES = {"send": "송신 · SMTP", "receive": "수신 · POP3 / IMAP"}


@dataclass
class Packet:
    time: str
    protocol: str
    source: str
    destination: str
    seq: str
    ack: str
    flags: str
    size: int
    lines: list = field(default_factory=list)

    ip_header: bytes = b""
    tcp_header: bytes = b""

    @classmethod
    def parse(cls, time, line):
        match = PACKET.fullmatch(line)
        if match:
            protocol, source, destination, seq, ack, flags, size = match.groups()
            return cls(time, protocol, source, destination, seq, ack, flags.strip(), int(size))
        return None

    @property
    def stage(self):
        return "send" if self.protocol == "SMTP" else "receive"

    @property
    def direction(self):
        port = self.source.rsplit(":", 1)[1]
        return "서버 → 클라이언트" if port in MAIL_PORTS[self.protocol] else "클라이언트 → 서버"

    @property
    def connection(self):
        return self.protocol, *sorted((self.source, self.destination))

    @property
    def starts_connection(self):
        return self.flags == "SYN"


def main():
    root = tk.Tk()
    root.title("메일 패킷 캡처")
    root.geometry("1150x720")
    root.minsize(790, 520)
    frame = ttk.Frame(root, padding=14)
    frame.pack(fill="both", expand=True)
    status = tk.StringVar(value="캡처 프로세스 연결 중")
    toolbar = ttk.Frame(frame)
    toolbar.pack(fill="x", pady=(0, 8))
    ttk.Label(toolbar, textvariable=status).pack(side="left")
    follow = tk.BooleanVar(value=True)
    ttk.Checkbutton(toolbar, text="최신 패킷 따라가기", variable=follow).pack(side="right")

    panes = ttk.Panedwindow(frame, orient="vertical")
    panes.pack(fill="both", expand=True)
    table_frame = ttk.Frame(panes)
    detail_frame = ttk.Frame(panes, padding=(0, 8, 0, 0))
    panes.add(table_frame, weight=3)
    panes.add(detail_frame, weight=2)

    columns = ("time", "direction", "flags", "bytes", "summary")
    table = ttk.Treeview(table_frame, columns=columns, selectmode="browse")
    for col, title, width in (
        ("#0", "메일 흐름 / TCP 연결", 250), ("time", "시간", 100),
        ("direction", "방향", 135), ("flags", "TCP 플래그", 90),
        ("bytes", "페이로드 B", 75), ("summary", "응용 계층 요약", 330),
    ):
        table.heading(col, text=title)
        table.column(col, width=width, minwidth=50, stretch=col in {"#0", "summary"})
    table.tag_configure("stage", font=("TkDefaultFont", 11, "bold"))
    scroll = ttk.Scrollbar(table_frame, command=table.yview)
    scroll.pack(side="right", fill="y")
    table.configure(yscrollcommand=scroll.set)
    table.pack(fill="both", expand=True)
    for key, label in STAGES.items():
        table.insert("", "end", iid=key, text=label, open=True, tags=("stage",))

    detail = ttk.Treeview(detail_frame, columns=("value",), selectmode="browse")
    detail.heading("#0", text="계층 / 필드")
    detail.heading("value", text="분석 값")
    detail.column("#0", width=240, stretch=False)
    detail.column("value", width=560)
    scroll_detail = ttk.Scrollbar(detail_frame, command=detail.yview)
    scroll_detail.pack(side="right", fill="y")
    detail.configure(yscrollcommand=scroll_detail.set)
    detail.pack(fill="both", expand=True)
    last_detail = None

    records = {}
    order = deque()
    connections = {}
    group_keys = {}
    inbox = Queue(maxsize=4096)
    current = None
    count = 0
    source = "대기 중"
    stage_counts = dict.fromkeys(STAGES, 0)

    def show(*_):
        nonlocal last_detail
        selected = table.selection()
        packet = records.get(selected[0]) if selected else None
        signature = (selected, bool(packet and packet.ip_header), len(packet.lines) if packet else 0)
        if signature == last_detail:
            return
        last_detail = signature
        detail.delete(*detail.get_children())
        if not packet:
            detail.insert("", "end", text="패킷 행을 선택하세요.")
            return

        def layer(title, fields):
            parent = detail.insert("", "end", text=title, open=True)
            for name, value in fields:
                detail.insert(parent, "end", text=name, values=(str(value),))
            return parent

        src, sport = packet.source.rsplit(":", 1)
        dst, dport = packet.destination.rsplit(":", 1)
        ip_fields = [("Source", src), ("Destination", dst)]
        if packet.ip_header:
            ip_fields.extend(network_fields(packet.ip_header))
        layer("Internet Protocol", ip_fields)
        transport = [("Source port", sport), ("Destination port", dport),
                     ("Sequence (raw)", packet.seq), ("Acknowledgment (raw)", packet.ack),
                     ("Payload length", packet.size)]
        if packet.tcp_header:
            transport.extend(tcp_fields(packet.tcp_header))
        else:
            transport.append(("Flags", packet.flags))
        layer("Transmission Control Protocol", transport)
        app = layer(packet.protocol, [])
        for line in packet.lines:
            item = detail.insert(app, "end", text="메시지", values=(line,), open=True)
            for name, value in application_fields(packet.protocol, line):
                detail.insert(item, "end", text=name, values=(str(value),))
        if not packet.lines:
            detail.insert(app, "end", text="페이로드 없음" if not packet.size else "완성된 메시지 없음")

    clear_protocol = tk.StringVar(value="SMTP")

    clear_protocol = tk.StringVar(value="SMTP")

    def clear_packets():
        nonlocal current

        protocol = clear_protocol.get()
        groups = {group for group, key in group_keys.items() if key[0] == protocol}
        if not groups:
            return

        kept = deque()
        for row, group in order:
            if group not in groups:
                kept.append((row, group))
                continue

            packet = records.pop(row)
            stage_counts[packet.stage] -= 1
            if current == row:
                current = None

        order.clear()
        order.extend(kept)

        for group in groups:
            key = group_keys.pop(group)
            connections.pop(key, None)
        table.delete(*groups)

        label = "캡처 종료" if status.get().startswith("캡처 종료") else source
        status.set(f"{label} · 캡처한 메일 패킷 {len(order)}개")
        for stage, title in STAGES.items():
            table.item(stage, text=f"{title} · {stage_counts[stage]}개")
        show()

    ttk.Button(toolbar, text="패킷 비우기", command=clear_packets).pack(
        side="right", padx=(0, 8)
    )
    ttk.Combobox(
        toolbar, textvariable=clear_protocol, values=tuple(MAIL_PORTS),
        state="readonly", width=7
    ).pack(side="right", padx=(0, 6))

    def pause_follow(_):
        follow.set(False)

    table.bind("<Button-1>", pause_follow)
    table.bind("<<TreeviewSelect>>", show)

    def add_packet(packet):
        nonlocal count
        key = packet.connection
        connection = connections.get(key)
        # Reused endpoints can start a new connection. A repeated SYN keeps its group.
        if connection is None or (packet.starts_connection and connection[1] != packet.seq):
            group = table.insert(packet.stage, "end", text=f"{packet.protocol} · {packet.time}",
                                 values=("", "", "", "", f"{packet.source} ↔ {packet.destination}"),
                                 open=True)
            connection = (group, packet.seq if packet.starts_connection else None)
            connections[key] = connection
            group_keys[group] = key
        count += 1
        stage_counts[packet.stage] += 1
        group = connection[0]
        row = table.insert(group, "end", text=f"#{count}", values=(
            packet.time, packet.direction, packet.flags, packet.size, "",
        ))
        records[row] = packet
        order.append((row, group))
        if len(order) > MAX_PACKETS:
            old, old_group = order.popleft()
            table.delete(old)
            old_packet = records.pop(old)
            stage_counts[old_packet.stage] -= 1
            if not table.get_children(old_group):
                table.delete(old_group)
                old_key = group_keys.pop(old_group)
                if connections[old_key][0] == old_group:
                    del connections[old_key]
        return row

    def read():
        for line in sys.stdin:
            stamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            inbox.put((stamp, line.rstrip("\n")))
        inbox.put((None, None))

    def update():
        nonlocal current, source
        changed = False
        ended = False
        for _ in range(350):
            try:
                stamp, line = inbox.get_nowait()
            except Empty:
                break
            if line is None:
                ended = True
                break
            packet = Packet.parse(stamp, line)
            if packet is not None:
                current = add_packet(packet)
                changed = True
            elif line.startswith("HEADERS ") and current:
                _, ip_hex, tcp_hex = line.split()
                records[current].ip_header = bytes.fromhex(ip_hex)
                records[current].tcp_header = bytes.fromhex(tcp_hex)
                changed = True
            elif line.startswith("  ") and current:
                lines = records[current].lines
                lines.append(line.strip())
                if len(lines) == 1:
                    table.set(current, "summary", lines[0][:96])
                changed = True
            elif line.startswith("Capturing "):
                source = line.split()[-1]
                changed = True
        if changed or ended:
            label = "캡처 종료" if ended else source
            status.set(f"{label} · 캡처한 메일 패킷 {len(order)}개")
            for key, title in STAGES.items():
                table.item(key, text=f"{title} · {stage_counts[key]}개")
            if follow.get() and current:
                table.selection_set(current)
                table.see(current)
            show()
        if not ended:
            root.after(50, update)

    Thread(target=read, daemon=True).start()
    root.after(10, update)
    root.mainloop()


if __name__ == "__main__":
    main()
