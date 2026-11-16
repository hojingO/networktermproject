"""
server.py — 중계(Relay) 서버

    python server.py

클라이언트 A, B의 TCP 연결을 받아서,
받은 프레임을 L7까지 벗겨 목적지(to)를 확인한 뒤
목적지 클라이언트용 새 헤더로 다시 감싸서 보낸다.
"""
import random
import socket
import threading

import config
from layers import (KIND_CLOSE, KIND_DATA, KIND_OPEN, ConnState, Env, HopContext,
                    LayerError, Stack, make_msg)
from visual import Visualizer
from wire import recv_frame, send_frame


class Conn:
    """서버가 관리하는 클라이언트 연결 하나."""

    def __init__(self, sock, addr):
        srv = config.HOSTS["SERVER"]
        self.sock = sock
        self.slot = None
        self.nick = None
        # 상대의 가상 IP/MAC은 아직 모름 → 첫 프레임의 L3/L2 헤더에서 학습
        self.ctx = HopContext(srv["ip"], srv["mac"], config.SERVER_PORT, None, None, addr[1])
        self.state = ConnState()
        self.label = f"client 127.0.0.1:{addr[1]}"


class RelayServer:
    def __init__(self):
        srv = config.HOSTS["SERVER"]
        self.viz = Visualizer("SERVER")
        self.stack = Stack(self.viz, config.XOR_KEY, config.ENCRYPT)
        self.clients = {}   # slot -> Conn
        self.label = f"SERVER {srv['ip']}:{config.SERVER_PORT}"

    # ───────── 송신 ─────────
    def send_to(self, conn, msg_type=None, text="", kind=KIND_DATA, msg=None):
        if msg is None:
            msg = make_msg(msg_type, "SERVER", "SERVER", conn.slot or "?", text)
        raw = self.stack.encapsulate(msg, Env(conn.ctx, conn.state, kind), self.label, conn.label)
        send_frame(conn.sock, raw)

    def broadcast_system(self, text, exclude):
        for other in list(self.clients.values()):
            if other is not exclude:
                try:
                    self.send_to(other, "SYSTEM", text)
                except OSError:
                    pass

    # ───────── L7 처리 ─────────
    def process(self, conn, msg) -> bool:
        """False를 반환하면 연결 종료."""
        viz, t = self.viz, msg["type"]

        if t == "LOGIN":
            conn.slot, conn.nick = msg["from"], msg["nick"]
            conn.state.session_id = random.randint(1000, 9999)
            conn.label = f"{conn.slot}({conn.nick}) {conn.ctx.remote_ip}:{conn.ctx.remote_port}"
            self.clients[conn.slot] = conn
            others = [c.nick for c in self.clients.values() if c is not conn]
            viz.route(f"LOGIN 처리\n"
                      f"- 사용자 {conn.nick} 를 슬롯 {conn.slot} 에 등록\n"
                      f"- 주소 테이블: {conn.ctx.remote_ip} / {conn.ctx.remote_mac} / port {conn.ctx.remote_port}\n"
                      f"- L5 세션 발급: sid={conn.state.session_id}")
            welcome = f"환영해 {conn.nick}! " + (f"{', '.join(others)} 님이 접속해 있어"
                                                 if others else "상대가 아직 없어, 조금 기다려줘")
            self.send_to(conn, "WELCOME", welcome, KIND_OPEN)
            self.broadcast_system(f"{conn.nick} 님이 들어왔어", exclude=conn)

        elif t == "CHAT":
            target = self.clients.get(msg["to"])
            if target is None:
                viz.route(f"CHAT 라우팅 실패: to={msg['to']} 는 아직 접속 안 함")
                self.send_to(conn, "SYSTEM", "상대가 아직 접속 안 했어")
            else:
                viz.route(f"CHAT 라우팅\n"
                          f"- L7까지 벗겨서 목적지 to={target.slot}({target.nick}) 확인\n"
                          f"- 내용: {conn.nick}: {msg['msg']}\n"
                          f"- 새 헤더로 재캡슐화  dst IP {target.ctx.remote_ip} / "
                          f"MAC {target.ctx.remote_mac} / port {target.ctx.remote_port}")
                self.send_to(target, msg=msg)

        elif t == "LOGOUT":
            viz.route(f"LOGOUT 처리: {conn.nick} 세션 sid={conn.state.session_id} 종료")
            self.send_to(conn, "BYE", f"잘 가 {conn.nick}", KIND_CLOSE)
            viz.fin(conn.label, self.label)
            return False

        return True

    # ───────── 연결별 스레드 ─────────
    def handle(self, sock, addr):
        conn, viz = Conn(sock, addr), self.viz
        with viz.lock:
            viz.section(f"새 TCP 연결 수락  127.0.0.1:{addr[1]}", "bold green")
            viz.handshake(conn.label, self.label)
        try:
            while True:
                raw = recv_frame(sock)
                if raw is None:
                    break
                with viz.lock:
                    env = Env(conn.ctx, conn.state)
                    try:
                        msg = self.stack.decapsulate(raw, env, conn.label, self.label)
                    except LayerError:
                        continue
                    if not self.process(conn, msg):
                        break
        except OSError:
            pass
        finally:
            with viz.lock:
                if conn.slot and self.clients.get(conn.slot) is conn:
                    del self.clients[conn.slot]
                    viz.info(f"{conn.label} 연결 종료")
                    self.broadcast_system(f"{conn.nick} 님이 나갔어", exclude=conn)
            try:
                sock.close()
            except OSError:
                pass

    def serve(self):
        srv = config.HOSTS["SERVER"]
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((config.SERVER_HOST, config.SERVER_PORT))
        listener.listen()
        with self.viz.lock:
            self.viz.banner([f"역할   중계 서버 (L7 relay)",
                             f"실제   {config.SERVER_HOST}:{config.SERVER_PORT} (TCP listen)",
                             f"가상   IP {srv['ip']}   MAC {srv['mac']}",
                             "",
                             "클라이언트 A, B 접속을 기다리는 중... (종료: Ctrl+C)"])
        try:
            while True:
                sock, addr = listener.accept()
                threading.Thread(target=self.handle, args=(sock, addr), daemon=True).start()
        except KeyboardInterrupt:
            self.viz.info("서버 종료")
        finally:
            listener.close()


if __name__ == "__main__":
    RelayServer().serve()
