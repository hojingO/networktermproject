"""
client.py — 채팅 클라이언트

    python client.py A 호진
    python client.py B 친구

명령어
    /quit             로그아웃 (L5 세션 종료 + TCP 4-way handshake)
    /corrupt 메시지    전송 중 비트 하나를 뒤집어서 L2 FCS 검사 실패를 시연
"""
import os
import socket
import sys
import threading

import config
from layers import (KIND_CLOSE, KIND_DATA, KIND_OPEN, ConnState, Env, HopContext,
                    LayerError, Stack, make_msg)
from visual import Visualizer
from wire import recv_frame, send_frame


def flip_bit(raw: bytes):
    """프레임 가운데 바이트의 비트 하나를 뒤집는다 (선로 잡음 흉내)."""
    i = len(raw) // 2
    return raw[:i] + bytes([raw[i] ^ 0x04]) + raw[i + 1:], i


def main():
    if len(sys.argv) < 3 or sys.argv[1].upper() not in ("A", "B"):
        print("사용법: python client.py <A|B> <닉네임>")
        sys.exit(1)

    slot, nick = sys.argv[1].upper(), sys.argv[2]
    peer = "B" if slot == "A" else "A"
    me, srv = config.HOSTS[slot], config.HOSTS["SERVER"]

    viz = Visualizer(f"CLIENT {slot}")
    stack = Stack(viz, config.XOR_KEY, config.ENCRYPT)

    try:
        sock = socket.create_connection((config.SERVER_HOST, config.SERVER_PORT))
    except ConnectionRefusedError:
        print("서버에 연결할 수 없어. server.py 를 먼저 실행해줘.")
        sys.exit(1)

    local_port = sock.getsockname()[1]      # OS가 정해준 실제 출발지 port
    ctx = HopContext(me["ip"], me["mac"], local_port, srv["ip"], srv["mac"], config.SERVER_PORT)
    state = ConnState()
    local = f"{slot}({nick}) {me['ip']}:{local_port}"
    remote = f"SERVER {srv['ip']}:{config.SERVER_PORT}"

    def send(msg_type, text, kind=KIND_DATA, to=peer, corrupt=False):
        msg = make_msg(msg_type, slot, nick, to, text)
        raw = stack.encapsulate(msg, Env(ctx, state, kind), local, remote)
        if corrupt:
            raw, idx = flip_bit(raw)
            viz.noise(idx)
        send_frame(sock, raw)

    def quit_now():
        try:
            sock.close()
        except OSError:
            pass
        viz.console.file.flush()
        os._exit(0)

    # ───────── 접속 + 로그인 ─────────
    with viz.lock:
        viz.banner([f"역할   클라이언트 {slot}  닉네임 {nick}",
                    f"실제   127.0.0.1:{local_port} -> {config.SERVER_HOST}:{config.SERVER_PORT} (TCP)",
                    f"가상   IP {me['ip']}   MAC {me['mac']}",
                    "",
                    "명령어  /quit 종료   /corrupt <메시지> 비트 오류 시연"])
        viz.handshake(local, remote)
        send("LOGIN", f"{nick} 로그인 요청", KIND_OPEN, to="SERVER")

    # ───────── 수신 스레드 ─────────
    def receiver():
        while True:
            raw = recv_frame(sock)
            with viz.lock:
                if raw is None:
                    viz.info("서버와 연결이 끊겼어")
                    quit_now()
                try:
                    msg = stack.decapsulate(raw, Env(ctx, state), remote, local)
                except LayerError:
                    viz.prompt()
                    continue
                t = msg["type"]
                if t == "WELCOME":
                    viz.system(msg["msg"])
                    viz.info(f"세션 수립 완료 (sid={state.session_id}). 메시지를 입력해.")
                elif t == "CHAT":
                    viz.message(msg["nick"], msg["msg"], msg["time"])
                elif t == "SYSTEM":
                    viz.system(msg["msg"])
                elif t == "BYE":
                    viz.system(msg["msg"])
                    viz.fin(local, remote)
                    quit_now()
                viz.prompt()

    threading.Thread(target=receiver, daemon=True).start()

    # ───────── 입력 루프 ─────────
    # 애니메이션 도중에 타이핑하면 화면에 글자가 섞여 보일 수 있지만,
    # 입력 내용 자체는 버퍼에 남아 있어서 Enter를 치면 정상 전송된다.
    while True:
        try:
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            line = "/quit"
        with viz.lock:
            if not line:
                viz.prompt()
                continue
            if line == "/quit":
                send("LOGOUT", f"{nick} 로그아웃", KIND_CLOSE, to="SERVER")
                break
            if line.startswith("/corrupt"):
                send("CHAT", line[len("/corrupt"):].strip() or "노이즈 테스트", corrupt=True)
            else:
                send("CHAT", line)
                viz.sent_ok()
            viz.prompt()

    threading.Event().wait(30)   # 서버의 BYE를 받으면 수신 스레드가 프로세스를 종료함
    quit_now()


if __name__ == "__main__":
    main()
