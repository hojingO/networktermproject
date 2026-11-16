"""
layers.py — OSI 7계층 캡슐화 / 역캡슐화

실제 TCP 연결은 OS 커널이 처리한다. 여기서는 L7~L2 헤더를 직접 바이트로 만들어
TCP payload에 싣고, 받는 쪽은 그 바이트를 진짜로 한 겹씩 파싱·검증하며 벗긴다.

  송신:  dict --L7--> JSON 문자열 --L6--> bytes --L5--> --L4(Segment)--> --L3(Packet)--> --L2(Frame)--> wire
  수신:  wire --L2--> --L3--> --L4--> --L5--> --L6--> JSON 문자열 --L7--> dict

모든 계층은 같은 인터페이스를 가진다.
    encapsulate(payload, env) -> (더 큰 payload, Info)
    decapsulate(payload, env) -> (더 작은 payload, Info)   # 검증 실패 시 LayerError
"""
from __future__ import annotations

import json
import socket
import struct
import time
import unicodedata
import zlib
from dataclasses import dataclass, field

# L5 세션 메시지 종류
KIND_DATA, KIND_OPEN, KIND_CLOSE = 0, 1, 2
KIND_NAME = {KIND_DATA: "DATA", KIND_OPEN: "OPEN", KIND_CLOSE: "CLOSE"}

# L4 TCP flag
TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10

ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6


# ─────────────────────────────── 공통 자료구조 ───────────────────────────────

class LayerError(Exception):
    """역캡슐화 중 검증 실패 → 해당 계층에서 프레임 폐기."""

    def __init__(self, layer: str, reason: str):
        super().__init__(f"{layer}: {reason}")
        self.layer = layer
        self.reason = reason


@dataclass
class HopContext:
    """이번 구간(hop)의 주소 정보. local = 나, remote = 상대."""
    local_ip: str
    local_mac: str
    local_port: int
    remote_ip: str | None     # 서버는 처음엔 모름 → 첫 프레임에서 학습
    remote_mac: str | None
    remote_port: int
    ttl: int = 64


@dataclass
class ConnState:
    """TCP 연결 하나에 딸린 상태 (seq/ack, 세션)."""
    seq: int = 1          # 내가 다음에 보낼 seq (Wireshark처럼 relative seq)
    ack: int = 1          # 상대에게서 다음에 받을 것으로 기대하는 seq
    session_id: int = 0   # 0 = 아직 세션 없음
    msg_no: int = 0
    ip_id: int = 0


@dataclass
class Env:
    ctx: HopContext
    state: ConnState
    kind: int = KIND_DATA


@dataclass
class Info:
    """시각화용 정보. 계층이 무엇을 붙였고/검사했는지."""
    layer: str
    name: str
    pdu: str
    style: str
    label: str                       # 프레임 그림에서 이 계층 헤더 칸에 들어갈 글자
    fields: list = field(default_factory=list)   # [(이름, 값)]
    header: bytes = b""
    trailer_label: str | None = None             # L2 FCS처럼 뒤에 붙는 것
    checks: list = field(default_factory=list)   # [(상태, 설명)]  상태: OK/LEARN/NEW/WARN


def make_msg(msg_type: str, frm: str, nick: str, to: str, text: str) -> dict:
    """L7 채팅 프로토콜 메시지."""
    return {
        "type": msg_type,   # LOGIN / WELCOME / CHAT / SYSTEM / LOGOUT / BYE
        "from": frm,        # 슬롯 (A / B / SERVER)
        "nick": nick,
        "to": to,
        "msg": text,
        "time": time.strftime("%H:%M:%S"),
    }


# ─────────────────────────────── 유틸 ───────────────────────────────

def _char_width(ch: str) -> int:
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def shorten(text: str, width: int) -> str:
    """한글 폭(2칸)을 고려해서 자르기."""
    if sum(map(_char_width, text)) <= width:
        return text
    out, w = "", 0
    for ch in text:
        cw = _char_width(ch)
        if w + cw > width - 2:
            break
        out += ch
        w += cw
    return out + ".."


def hexs(data: bytes, limit: int = 10) -> str:
    s = " ".join(f"{b:02X}" for b in data[:limit])
    return s + (f" ..(+{len(data) - limit}B)" if len(data) > limit else "")


def internet_checksum(data: bytes) -> int:
    """IP/TCP에서 쓰는 16bit 1의 보수 합 checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def bytes_to_mac(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


# ─────────────────────────────── L7 Application ───────────────────────────────

class Application:
    LAYER, NAME, PDU, STYLE = "L7", "Application", "Data", "bright_white"
    REQUIRED = ("type", "from", "nick", "to", "msg", "time")

    def _info(self, msg: dict, text: str) -> Info:
        return Info(self.LAYER, self.NAME, self.PDU, self.STYLE,
                    label=f"DATA\n{msg['type']}\n{shorten(msg['msg'], 14)}",
                    fields=[("message", text)])

    def encapsulate(self, msg: dict, env: Env):
        text = json.dumps(msg, ensure_ascii=False, separators=(",", ":"))
        return text, self._info(msg, text)

    def decapsulate(self, text: str, env: Env):
        try:
            msg = json.loads(text)
        except json.JSONDecodeError as e:
            raise LayerError("L7", f"JSON 파싱 실패 ({e})")
        missing = [k for k in self.REQUIRED if k not in msg]
        if missing:
            raise LayerError("L7", f"필수 필드 누락 {missing}")
        info = self._info(msg, text)
        info.checks = [
            ("OK", "채팅 프로토콜 메시지 파싱 성공"),
            ("OK", f"type={msg['type']}  from={msg['nick']}({msg['from']})  to={msg['to']}"),
        ]
        return msg, info


# ─────────────────────────────── L6 Presentation ───────────────────────────────

class Presentation:
    """문자열 ↔ 바이트 변환(인코딩) + 암호화. 헤더: [encoding 1B][flags 1B]"""
    LAYER, NAME, PDU, STYLE = "L6", "Presentation", "Data", "magenta"
    HDR = struct.Struct("!BB")
    ENC_UTF8 = 1
    FLAG_XOR = 0x01

    def __init__(self, key: int, encrypt: bool = True):
        self.key = key
        self.encrypt = encrypt

    def _label(self, encrypted: bool) -> str:
        return f"PRESENT\nUTF-8\n{'XOR' if encrypted else 'plain'}"

    def encapsulate(self, text: str, env: Env):
        plain = text.encode("utf-8")
        body = xor_bytes(plain, self.key) if self.encrypt else plain
        hdr = self.HDR.pack(self.ENC_UTF8, self.FLAG_XOR if self.encrypt else 0)
        fields = [("encoding", f"문자열 {len(text)}자 → UTF-8 {len(plain)}B"),
                  ("plain", hexs(plain))]
        if self.encrypt:
            fields.append(("encrypted", f"{hexs(body)}   (XOR key 0x{self.key:02X})"))
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE,
                    label=self._label(self.encrypt), fields=fields, header=hdr)
        return hdr + body, info

    def decapsulate(self, data: bytes, env: Env):
        if len(data) < self.HDR.size:
            raise LayerError("L6", "헤더 길이 부족")
        enc, flags = self.HDR.unpack_from(data)
        if enc != self.ENC_UTF8:
            raise LayerError("L6", f"모르는 인코딩 {enc}")
        body = data[self.HDR.size:]
        encrypted = bool(flags & self.FLAG_XOR)
        plain = xor_bytes(body, self.key) if encrypted else body
        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            raise LayerError("L6", "UTF-8 디코딩 실패 (데이터 손상)")
        checks = []
        if encrypted:
            checks.append(("OK", f"XOR 복호화  {hexs(body, 6)} → {hexs(plain, 6)}"))
        checks.append(("OK", f"UTF-8 디코딩 {len(plain)}B → 문자열 {len(text)}자"))
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE,
                    label=self._label(encrypted), header=data[:self.HDR.size], checks=checks)
        return text, info


# ─────────────────────────────── L5 Session ───────────────────────────────

class Session:
    """대화(세션) 관리. 헤더: [session_id 4B][msg_no 2B][kind 1B]"""
    LAYER, NAME, PDU, STYLE = "L5", "Session", "Data", "cyan"
    HDR = struct.Struct("!IHB")

    def _label(self, sid, no, kind) -> str:
        return f"SESSION\nsid {sid}\n#{no} {KIND_NAME.get(kind, '?')}"

    def encapsulate(self, data: bytes, env: Env):
        st = env.state
        st.msg_no = (st.msg_no + 1) & 0xFFFF
        hdr = self.HDR.pack(st.session_id, st.msg_no, env.kind)
        sid_txt = st.session_id if st.session_id else "0 (미할당 → 서버에 발급 요청)"
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE,
                    label=self._label(st.session_id, st.msg_no, env.kind),
                    fields=[("session", sid_txt), ("msg_no", st.msg_no),
                            ("kind", KIND_NAME[env.kind])],
                    header=hdr)
        return hdr + data, info

    def decapsulate(self, data: bytes, env: Env):
        if len(data) < self.HDR.size:
            raise LayerError("L5", "헤더 길이 부족")
        sid, no, kind = self.HDR.unpack_from(data)
        st = env.state
        env.kind = kind
        checks = []
        if kind == KIND_OPEN:
            if sid == 0:
                checks.append(("NEW", "세션 개설 요청 (sid 미할당)"))
            elif st.session_id == 0:
                st.session_id = sid
                checks.append(("NEW", f"서버가 발급한 세션 sid={sid} 수립"))
            elif sid == st.session_id:
                checks.append(("OK", f"sid={sid} 일치"))
            else:
                raise LayerError("L5", f"세션 불일치 (받은 {sid}, 내 세션 {st.session_id})")
        else:
            if sid != st.session_id:
                raise LayerError("L5", f"세션 불일치 (받은 {sid}, 내 세션 {st.session_id})")
            checks.append(("OK", f"sid={sid} 일치, 메시지 #{no}"))
            if kind == KIND_CLOSE:
                checks.append(("OK", "세션 종료 요청"))
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE,
                    label=self._label(sid, no, kind), header=data[:self.HDR.size], checks=checks)
        return data[self.HDR.size:], info


# ─────────────────────────────── L4 Transport ───────────────────────────────

class Transport:
    """TCP 헤더 (단순화). [src 2B][dst 2B][seq 4B][ack 4B][flags 1B][window 2B][checksum 2B]"""
    LAYER, NAME, PDU, STYLE = "L4", "Transport", "Segment", "green"
    HDR = struct.Struct("!HHIIBHH")

    def _label(self, sp, dp, seq) -> str:
        return f"TCP\n{sp}->{dp}\nseq {seq}"

    def encapsulate(self, data: bytes, env: Env):
        ctx, st = env.ctx, env.state
        flags, window = TCP_PSH | TCP_ACK, 65535
        seq, ack = st.seq, st.ack
        zeroed = self.HDR.pack(ctx.local_port, ctx.remote_port, seq, ack, flags, window, 0)
        cs = internet_checksum(zeroed + data)
        hdr = self.HDR.pack(ctx.local_port, ctx.remote_port, seq, ack, flags, window, cs)
        st.seq += len(data)
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE,
                    label=self._label(ctx.local_port, ctx.remote_port, seq),
                    fields=[("port", f"{ctx.local_port} → {ctx.remote_port}"),
                            ("seq/ack", f"seq={seq}  ack={ack}  (payload {len(data)}B → 다음 seq={st.seq})"),
                            ("flags", "PSH+ACK"), ("checksum", f"0x{cs:04X}")],
                    header=hdr)
        return hdr + data, info

    def decapsulate(self, data: bytes, env: Env):
        if len(data) < self.HDR.size:
            raise LayerError("L4", "헤더 길이 부족")
        ctx, st = env.ctx, env.state
        sp, dp, seq, ack, flags, window, cs = self.HDR.unpack_from(data)
        payload = data[self.HDR.size:]
        calc = internet_checksum(self.HDR.pack(sp, dp, seq, ack, flags, window, 0) + payload)
        if calc != cs:
            raise LayerError("L4", f"checksum 불일치 (헤더 0x{cs:04X}, 계산 0x{calc:04X})")
        if dp != ctx.local_port:
            raise LayerError("L4", f"목적지 port {dp} ≠ 내 port {ctx.local_port}")
        checks = [("OK", f"checksum 0x{cs:04X} 일치"),
                  ("OK", f"dst port {dp} = 내 port")]
        if seq != st.ack:
            checks.append(("WARN", f"seq {seq} ≠ 기대값 {st.ack}  (앞 세그먼트 유실)"))
        else:
            checks.append(("OK", f"seq {seq} 순서 정상 → 다음 기대 seq {seq + len(payload)}"))
        st.ack = seq + len(payload)
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE,
                    label=self._label(sp, dp, seq), header=data[:self.HDR.size], checks=checks)
        return payload, info


# ─────────────────────────────── L3 Network ───────────────────────────────

class Network:
    """실제 IPv4 헤더와 같은 20바이트 구조."""
    LAYER, NAME, PDU, STYLE = "L3", "Network", "Packet", "blue"
    HDR = struct.Struct("!BBHHHBBH4s4s")

    def _label(self, src, dst, ttl) -> str:
        return f"IPv4\n.{src.split('.')[-1]}->.{dst.split('.')[-1]}\nTTL {ttl}"

    def encapsulate(self, data: bytes, env: Env):
        ctx, st = env.ctx, env.state
        st.ip_id = (st.ip_id + 1) & 0xFFFF
        total = self.HDR.size + len(data)
        src, dst = socket.inet_aton(ctx.local_ip), socket.inet_aton(ctx.remote_ip)
        args = [0x45, 0, total, st.ip_id, 0x4000, ctx.ttl, IPPROTO_TCP, 0, src, dst]
        args[7] = internet_checksum(self.HDR.pack(*args))
        hdr = self.HDR.pack(*args)
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE,
                    label=self._label(ctx.local_ip, ctx.remote_ip, ctx.ttl),
                    fields=[("IP", f"{ctx.local_ip} → {ctx.remote_ip}"),
                            ("TTL/proto", f"TTL={ctx.ttl}  protocol=6 (TCP)  id={st.ip_id}"),
                            ("length", f"{total}B"), ("checksum", f"0x{args[7]:04X}")],
                    header=hdr)
        return hdr + data, info

    def decapsulate(self, data: bytes, env: Env):
        if len(data) < self.HDR.size:
            raise LayerError("L3", "헤더 길이 부족")
        ctx = env.ctx
        ver_ihl, _tos, total, _id, _frag, ttl, proto, cs, src, dst = self.HDR.unpack_from(data)
        if ver_ihl >> 4 != 4:
            raise LayerError("L3", "IPv4 아님")
        if internet_checksum(data[:self.HDR.size]) != 0:
            raise LayerError("L3", f"헤더 checksum 불일치 (0x{cs:04X})")
        if total != len(data):
            raise LayerError("L3", f"길이 불일치 (헤더 {total}B, 실제 {len(data)}B)")
        src_ip, dst_ip = socket.inet_ntoa(src), socket.inet_ntoa(dst)
        if dst_ip != ctx.local_ip:
            raise LayerError("L3", f"목적지 IP {dst_ip} ≠ 내 IP {ctx.local_ip}")
        if ttl == 0:
            raise LayerError("L3", "TTL 만료")
        if proto != IPPROTO_TCP:
            raise LayerError("L3", f"protocol {proto} ≠ TCP")
        checks = [("OK", f"checksum 0x{cs:04X} 일치"),
                  ("OK", f"dst IP {dst_ip} = 내 IP,  TTL={ttl},  protocol=TCP")]
        if ctx.remote_ip is None:
            ctx.remote_ip = src_ip
            checks.append(("LEARN", f"보낸 쪽 IP {src_ip} 학습"))
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE,
                    label=self._label(src_ip, dst_ip, ttl), header=data[:self.HDR.size], checks=checks)
        return data[self.HDR.size:], info


# ─────────────────────────────── L2 Data Link ───────────────────────────────

class DataLink:
    """Ethernet II. [dst MAC 6B][src MAC 6B][EtherType 2B] ... [FCS 4B(CRC32)]"""
    LAYER, NAME, PDU, STYLE = "L2", "Data Link", "Frame", "dark_orange"
    HDR = struct.Struct("!6s6sH")
    FCS = struct.Struct("!I")

    def _labels(self, src, dst, fcs):
        return (f"ETHERNET\n:{src[-2:]}->:{dst[-2:]}\n0x0800",
                f"FCS\n{fcs >> 16:04X}\n{fcs & 0xFFFF:04X}")

    def encapsulate(self, data: bytes, env: Env):
        ctx = env.ctx
        hdr = self.HDR.pack(mac_to_bytes(ctx.remote_mac), mac_to_bytes(ctx.local_mac), ETHERTYPE_IPV4)
        fcs = zlib.crc32(hdr + data) & 0xFFFFFFFF
        label, trailer = self._labels(ctx.local_mac, ctx.remote_mac, fcs)
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE, label=label, trailer_label=trailer,
                    fields=[("MAC", f"{ctx.local_mac} → {ctx.remote_mac}"),
                            ("EtherType", "0x0800 (IPv4)"),
                            ("FCS", f"CRC32 = 0x{fcs:08X}  (프레임 맨 뒤에 붙음)")],
                    header=hdr)
        return hdr + data + self.FCS.pack(fcs), info

    def decapsulate(self, data: bytes, env: Env):
        if len(data) < self.HDR.size + self.FCS.size:
            raise LayerError("L2", "프레임 길이 부족")
        ctx = env.ctx
        body, (fcs,) = data[:-self.FCS.size], self.FCS.unpack(data[-self.FCS.size:])
        calc = zlib.crc32(body) & 0xFFFFFFFF
        if calc != fcs:
            raise LayerError("L2", f"FCS 불일치 (프레임 0x{fcs:08X}, 계산 0x{calc:08X}) → 전송 중 비트 오류")
        dst, src, etype = self.HDR.unpack_from(body)
        dst_mac, src_mac = bytes_to_mac(dst), bytes_to_mac(src)
        if dst_mac != ctx.local_mac.upper():
            raise LayerError("L2", f"목적지 MAC {dst_mac} ≠ 내 MAC")
        if etype != ETHERTYPE_IPV4:
            raise LayerError("L2", f"EtherType 0x{etype:04X} ≠ IPv4")
        checks = [("OK", f"FCS(CRC32) 0x{fcs:08X} 일치 → 비트 오류 없음"),
                  ("OK", f"dst MAC {dst_mac} = 내 MAC")]
        if ctx.remote_mac is None:
            ctx.remote_mac = src_mac
            checks.append(("LEARN", f"보낸 쪽 MAC {src_mac} 학습 (주소 테이블 등록)"))
        label, trailer = self._labels(src_mac, dst_mac, fcs)
        info = Info(self.LAYER, self.NAME, self.PDU, self.STYLE, label=label, trailer_label=trailer,
                    header=body[:self.HDR.size], checks=checks)
        return body[self.HDR.size:], info


# ─────────────────────────────── 프로토콜 스택 ───────────────────────────────

class Stack:
    """L7→L2 순서로 감싸고, L2→L7 순서로 벗긴다. L1은 시각화(비트 전송)만 담당."""

    def __init__(self, viz, xor_key: int, encrypt: bool = True):
        self.viz = viz
        self.layers = [Application(), Presentation(xor_key, encrypt), Session(),
                       Transport(), Network(), DataLink()]

    def encapsulate(self, msg: dict, env: Env, src_label: str, dst_label: str) -> bytes:
        viz = self.viz
        viz.section(f"송신  {src_label}  ->  {dst_label}   [{msg['type']}]", "bold white")
        data, stack = msg, []
        for layer in self.layers:
            data, info = layer.encapsulate(data, env)
            stack.append(info)
            viz.encap_step(info, stack)
        viz.physical(src_label, dst_label, data, sending=True)
        return data

    def decapsulate(self, raw: bytes, env: Env, src_label: str, dst_label: str) -> dict:
        viz = self.viz
        viz.section(f"수신  {src_label}  ->  {dst_label}", "bold white")
        viz.physical(src_label, dst_label, raw, sending=False)
        infos, data, error = [], raw, None
        for layer in reversed(self.layers):
            try:
                data, info = layer.decapsulate(data, env)
            except LayerError as e:
                error = e
                break
            infos.append(info)
        viz.decap_replay(infos, error)
        if error:
            raise error
        return data
