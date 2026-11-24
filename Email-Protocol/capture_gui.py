"""Run with ./mail_capture INTERFACE | python3 capture_gui.py."""
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

    ip_info = tk.StringVar(value="패킷을 선택해.")
    tcp_info = tk.StringVar()
    app_title = ttk.LabelFrame(detail_frame, text="응용 계층", padding=(8, 4))
    for title, value in (("IP 헤더", ip_info), ("TCP 헤더", tcp_info)):
        section = ttk.LabelFrame(detail_frame, text=title, padding=(8, 4))
        section.pack(fill="x", pady=(0, 4))
        ttk.Label(section, textvariable=value).pack(anchor="w")
    app_title.pack(fill="both", expand=True)
    detail_scroll = ttk.Scrollbar(app_title)
    detail_scroll.pack(side="right", fill="y")
    detail = tk.Text(app_title, height=5, wrap="word", state="disabled",
                     yscrollcommand=detail_scroll.set)
    detail_scroll.configure(command=detail.yview)
    detail.pack(fill="both", expand=True)

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
        selected = table.selection()
        packet = records.get(selected[0]) if selected else None
        lines = []
        if packet:
            src, sport = packet.source.rsplit(":", 1)
            dst, dport = packet.destination.rsplit(":", 1)
            ip_info.set(f"출발지 IP {src}    →    목적지 IP {dst}")
            tcp_info.set(
                f"출발지 포트 {sport}  →  목적지 포트 {dport}    "
                f"Seq {packet.seq}    Ack {packet.ack}    "
                f"플래그 {packet.flags or '—'}    페이로드 {packet.size} B"
            )
            app_title.configure(text=f"응용 계층 · {packet.protocol}")
            lines = packet.lines
            message = ("이 패킷의 TCP 페이로드는 0 B야." if not packet.size else
                       "이 패킷에서 완성된 응용 계층 줄이 없어.")
        else:
            ip_info.set("연결을 펼치고 패킷 행을 선택해.")
            tcp_info.set("")
            app_title.configure(text="응용 계층")
            message = ""
        detail.configure(state="normal")
        detail.delete("1.0", "end")
        detail.insert("1.0", "\n".join(lines) if lines else message)
        detail.configure(state="disabled")

    def clear_packets():
        nonlocal current, count

        for key, title in STAGES.items():
            groups = table.get_children(key)
            if groups:
                table.delete(*groups)
            stage_counts[key] = 0
            table.item(key, text=f"{title} · 0개")

        records.clear()
        order.clear()
        connections.clear()
        group_keys.clear()
        current = None
        count = 0

        if status.get().startswith("캡처 종료"):
            status.set("캡처 종료 · 캡처한 메일 패킷 0개")
        else:
            status.set(f"{source} · 캡처한 메일 패킷 0개")

        show()

    ttk.Button(toolbar, text="패킷 비우기", command=clear_packets).pack(
        side="right", padx=(0, 8)
    )

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
            del records[old]
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
            status.set(f"{label} · 캡처한 메일 패킷 {count}개")
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
