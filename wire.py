"""
wire.py — 실제 TCP 소켓 송수신

TCP는 'stream'이라 메시지 경계가 없다.
send를 두 번 하면 recv 한 번에 붙어서 올 수도, 한 번 보낸 게 쪼개져 올 수도 있다.
그래서 맨 앞에 4바이트 길이(length prefix)를 붙여서 프레임 경계를 직접 만든다.

    [ 4B 길이 ][ 시뮬레이션 프레임 (L2 헤더 ... FCS) ]
"""
import struct

LEN = struct.Struct("!I")
MAX_FRAME = 1 << 20  # 1MB 이상은 비정상으로 간주


def send_frame(sock, data: bytes) -> None:
    sock.sendall(LEN.pack(len(data)) + data)


def _recv_exact(sock, n: int):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:          # 상대가 연결을 닫음
            return None
        buf += chunk
    return bytes(buf)


def recv_frame(sock):
    """프레임 하나를 통째로 받는다. 연결이 끊기면 None."""
    try:
        head = _recv_exact(sock, LEN.size)
        if head is None:
            return None
        (length,) = LEN.unpack(head)
        if length > MAX_FRAME:
            return None
        return _recv_exact(sock, length)
    except OSError:
        return None
