# OSI 7-Layer Chat (캡슐화 시뮬레이터)

클라이언트 - 서버 - 클라이언트 구조의 채팅 프로그램.
메시지를 보낼 때마다 L7 → L1 캡슐화, 받을 때마다 L1 → L7 역캡슐화 과정을 터미널 애니메이션으로 보여준다.

## 실행 (한 PC, 터미널 3개)

```bash
pip install -r requirements.txt

python server.py          # 터미널 1
python client.py A A    # 터미널 2
python client.py B B    # 터미널 3
```

- 터미널 창 폭은 80칸 이상 권장 (Windows Terminal / VS Code 터미널 추천)
- 애니메이션 속도: 환경변수 `OSI_ANIM` (기본 1.0, 0.5 = 빠르게, 2 = 느리게, 0 = 끔)

## 명령어

| 입력 | 동작 |
|---|---|
| 일반 텍스트 | 상대에게 채팅 전송 |
| `/corrupt 메시지` | 전송 중 비트 1개를 뒤집음 → 서버 L2에서 FCS 불일치로 폐기, 다음 메시지에서 L4 seq 유실 경고 |
| `/quit` | L5 세션 종료 + TCP 4-way handshake |

## 구조

| 파일 | 역할 |
|---|---|
| `layers.py` | L7~L2 계층 클래스 (`encapsulate` / `decapsulate`), 실제 바이트로 헤더 생성·검증 |
| `visual.py` | rich 기반 애니메이션 (프레임 그림, ASCII 강아지 L1, handshake) |
| `wire.py` | 실제 TCP 송수신, 4바이트 length prefix로 메시지 경계 처리 |
| `server.py` | L7 relay 서버: 받은 프레임을 L7까지 벗겨 목적지 확인 후 재캡슐화 |
| `client.py` | 입력 스레드 + 수신 스레드 |
| `config.py` | 가상 IP/MAC, 포트, 애니메이션 속도 |

## 계층별 구현

| 계층 | PDU | 헤더 | 검증 |
|---|---|---|---|
| L7 Application | Data | JSON 채팅 메시지 | 필수 필드 |
| L6 Presentation | Data | 인코딩 + 암호화 플래그 (2B) | XOR 복호화, UTF-8 디코딩 |
| L5 Session | Data | session_id, msg_no, kind (7B) | 세션 발급/일치/종료 |
| L4 Transport | Segment | port, seq, ack, flags, checksum (17B) | checksum, dst port, seq 순서 |
| L3 Network | Packet | 실제 IPv4 구조 (20B) | header checksum, dst IP, TTL |
| L2 Data Link | Frame | Ethernet II (14B) + FCS CRC32 (4B) | FCS, dst MAC |
| L1 Physical | Bits | - | 비트열 전송 애니메이션 |

