"""
visual.py — rich 기반 터미널 시각화

- encap_step   : 계층 하나가 헤더를 붙일 때마다 프레임 그림이 바깥으로 커짐
- decap_replay : 수신 시 바깥 헤더부터 한 겹씩 벗겨지며 검증 결과 표시
- physical     : L1, 강아지가 FRAME 봉투를 물고 선로를 달리는 애니메이션
- handshake/fin: TCP 3-way / 4-way handshake 화살표 애니메이션

여러 스레드(송신/수신)가 동시에 그리면 화면이 깨지므로
호출하는 쪽에서 viz.lock을 잡고 사용한다.
"""
from __future__ import annotations

import sys
import threading
import time

from rich import box
from rich.cells import cell_len
from rich.console import Console
from rich.live import Live
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

import config

# ASCII 강아지 우편배달부 (이모지 없음, 순수 ASCII)
DOG_FRAMES = [
    ["     __    .-------.",
     " (___()'`;=| FRAME |",
     " /,    /`  '-------'",
     ' \\\\"--\\\\'],
    ["     __    .-------.",
     " (___()'`;=| FRAME |",
     " /,    /`  '-------'",
     ' //"--//'],
]
DOG_WIDTH = max(len(line) for frame in DOG_FRAMES for line in frame)

CHECK_STYLE = {"OK": "green", "LEARN": "cyan", "NEW": "cyan", "WARN": "yellow", "FAIL": "bold red"}


def hexdump(data: bytes, limit: int = 20) -> str:
    s = " ".join(f"{b:02X}" for b in data[:limit])
    return s + (f" ..(+{len(data) - limit}B)" if len(data) > limit else "")


def render_row(stack) -> Table:
    """stack: [L7, L6, ..., L2] (안쪽→바깥쪽) 를 받아 [L2|L3|...|DATA|FCS] 한 줄 그림으로."""
    headers = [i for i in stack if i.layer != "L7"]
    data = stack[0] if stack and stack[0].layer == "L7" else None
    cells = [(i.label, i.style) for i in reversed(headers)]            # 바깥 헤더가 왼쪽
    cells.append((data.label, data.style) if data else ("DATA\n????", "dim"))
    cells += [(i.trailer_label, i.style) for i in headers if i.trailer_label]  # FCS는 맨 뒤
    table = Table(show_header=False, box=box.HEAVY, padding=(0, 1))
    for _ in cells:
        table.add_column(justify="center", vertical="middle")
    table.add_row(*(Text(label, style=f"bold {style}") for label, style in cells))
    return table


class Visualizer:
    def __init__(self, node: str):
        self.node = node
        self.console = Console(highlight=False)
        self.lock = threading.RLock()
        self.animate = config.ANIM_SCALE > 0 and self.console.is_terminal

    # ───────── 기본 출력 ─────────
    def _pause(self, sec: float):
        if config.ANIM_SCALE > 0:
            time.sleep(sec * config.ANIM_SCALE)

    def _animate(self, render, frames: int, delay: float):
        if not self.animate:
            self.console.print(render(frames - 1))
            return
        with Live(render(0), console=self.console, refresh_per_second=30, transient=False) as live:
            for i in range(frames):
                live.update(render(i), refresh=True)
                time.sleep(delay * config.ANIM_SCALE)

    def banner(self, lines):
        body = Text("\n".join(DOG_FRAMES[0]), style="yellow")
        body.append("\n\n" + "\n".join(lines))
        self.console.print(Panel(body, title=Text(f" OSI 7-Layer Chat :: {self.node} "),
                                 border_style="bold", expand=False))

    def section(self, title: str, style: str = "bold white"):
        self.console.print()
        self.console.print(Rule(Text(title), style=style))

    def info(self, text: str):
        self.console.print(Text(f"  * {text}", style="dim"))

    def system(self, text: str):
        self.console.print(Text(f"  [SYSTEM] {text}", style="bold magenta"))

    def noise(self, index: int):
        self.console.print(Text(f"  [NOISE] 선로 잡음! byte {index}의 비트 하나가 뒤집힘", style="bold red"))

    def sent_ok(self):
        self.console.print(Text("  [OK] 전송 완료", style="bold green"))

    def route(self, text: str):
        self.console.print(Padding(Panel(Text(text), title=Text(" SERVER 처리 (L7 relay) "),
                                         border_style="bold blue", expand=False), (0, 0, 0, 2)))

    def message(self, nick: str, text: str, when: str = "", outgoing: bool = False):
        style = "bold green" if outgoing else "bold cyan"
        self.console.print(Padding(Panel(Text(text), title=Text(f" {nick} "), subtitle=Text(f" {when} "),
                                         border_style=style, expand=False), (0, 0, 0, 2)))

    def prompt(self):
        self.console.print(Text("나> ", style="bold"), end="")
        sys.stdout.flush()

    # ───────── 캡슐화 / 역캡슐화 ─────────
    def encap_step(self, info, stack):
        c = self.console
        title = Text(f"  v {info.layer} {info.name:<13}", style=f"bold {info.style}")
        title.append(f"->  {info.pdu}", style="bold")
        c.print(title)
        c.print(Padding(render_row(stack), (0, 0, 0, 4)))
        for key, val in info.fields:
            c.print(Text(f"      {key:<10} {val}", style="dim"))
        if info.header:
            c.print(Text(f"      header {len(info.header):>2}B  {hexdump(info.header)}", style=info.style))
        self._pause(config.STEP_DELAY)

    def decap_replay(self, infos, error):
        c = self.console
        if infos or error:
            c.print(Text("  수신한 프레임", style="bold"))
            c.print(Padding(render_row(list(reversed(infos))), (0, 0, 0, 4)))
            self._pause(config.STEP_DELAY)
        for i, info in enumerate(infos):
            title = Text(f"  ^ {info.layer} {info.name:<13}", style=f"bold {info.style}")
            title.append(f"<-  {info.pdu} 헤더 제거", style="bold")
            c.print(title)
            for status, msg in info.checks:
                c.print(Text(f"      [{status}] {msg}", style=CHECK_STYLE.get(status, "")))
            remaining = list(reversed(infos[i + 1:]))
            if remaining:
                c.print(Padding(render_row(remaining), (0, 0, 0, 4)))
            self._pause(config.STEP_DELAY)
        if error:
            c.print(Text(f"  [FAIL] {error.layer}: {error.reason}", style="bold red"))
            c.print(Text("  -> 이 계층에서 프레임 폐기, 윗 계층으로 올라가지 않음", style="red"))
            self._pause(config.STEP_DELAY)

    # ───────── L1 Physical ─────────
    def physical(self, src: str, dst: str, raw: bytes, sending: bool):
        mark, verb = ("v", "송신") if sending else ("^", "수신")
        self.console.print(Text(f"  {mark} L1 Physical    ->  Bits  ({len(raw)}B = {len(raw) * 8} bits {verb})",
                                style="bold yellow"))
        bits = "".join(f"{b:08b}" for b in raw)
        track, frames = 62, 36
        head, tail = f"[{src}]", f"[{dst}]"
        gap = " " * max(2, track - cell_len(head) - cell_len(tail))

        def render(i):
            pos = round(i * (track - DOG_WIDTH) / (frames - 1))
            lines = ["  " + head + gap + tail]
            lines += ["  " + " " * pos + line for line in DOG_FRAMES[i % 2]]
            lines.append("  " + "=" * track)
            start = (i * 8) % len(bits)
            window = (bits * 2)[start:start + 56]
            lines.append("  " + " ".join(window[k:k + 8] for k in range(0, 56, 8)) + " ...")
            pct = round(100 * (i + 1) / frames)
            lines.append(f"  [{'#' * (pct // 5):<20}] {pct:3d}%")
            return Text("\n".join(lines), style="yellow")

        self._animate(render, frames, config.DOG_DELAY)

    # ───────── TCP handshake ─────────
    def _exchange(self, left: str, right: str, steps, style: str):
        width, frames = 50, 14
        gap = " " * max(2, width + 2 - cell_len(left) - cell_len(right))
        self.console.print(Text(f"    {left}{gap}{right}", style="bold"))
        for name, detail, to_right in steps:
            label = f"{name}  {detail}".center(width)

            def render(k, label=label, to_right=to_right):
                n = max(1, int((width - 1) * (k + 1) / frames))
                arrow = ("-" * n + ">").ljust(width) if to_right else ("<" + "-" * n).rjust(width)
                return Text(f"    |{label}|\n    |{arrow}|", style=style)

            self._animate(render, frames, 0.04)

    def handshake(self, left: str, right: str):
        self.section("L4 Transport  TCP 3-way handshake (연결 수립)", "bold green")
        self._exchange(left, right, [("SYN", "seq=x", True),
                                     ("SYN+ACK", "seq=y, ack=x+1", False),
                                     ("ACK", "ack=y+1", True)], "green")
        self.console.print(Text("    => ESTABLISHED   (실제 handshake는 OS 커널이 connect()/accept()에서 수행, 화면은 그 과정을 재현)",
                                style="dim green"))

    def fin(self, left: str, right: str):
        self.section("L4 Transport  TCP 4-way handshake (연결 종료)", "bold red")
        self._exchange(left, right, [("FIN", "seq=u", True),
                                     ("ACK", "ack=u+1", False),
                                     ("FIN", "seq=w", False),
                                     ("ACK", "ack=w+1", True)], "red")
        self.console.print(Text("    => CLOSED", style="dim red"))
