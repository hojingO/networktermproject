"""
config.py — 공통 설정

한 PC(localhost)에서 터미널 3개로 돌리기 때문에 실제 IP는 전부 127.0.0.1이다.
L3/L2 계층을 보여주기 위해 노드마다 '가상' IP/MAC을 하나씩 정해둔다.
(포트 번호는 가상이 아니라 실제 TCP 소켓 포트를 그대로 쓴다.)
"""
import os

# 실제 TCP 연결 대상
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000

# 가상 주소 테이블 (L3 IP / L2 MAC)
HOSTS = {
    "SERVER": {"ip": "10.0.0.1", "mac": "AA:BB:CC:00:00:01"},
    "A":      {"ip": "10.0.0.2", "mac": "AA:BB:CC:00:00:02"},
    "B":      {"ip": "10.0.0.3", "mac": "AA:BB:CC:00:00:03"},
}

# L6 Presentation: 간단한 XOR 암호화 (보안용 아님, 표현 계층 시연용)
ENCRYPT = True
XOR_KEY = 0x5A

# 애니메이션 속도 배율 (1.0 = 기본, 2.0 = 두 배 느리게, 0 = 애니메이션 없음)
#   예) Windows:  set OSI_ANIM=0.5   /  macOS·Linux:  OSI_ANIM=0.5 python client.py A 호진
ANIM_SCALE = float(os.environ.get("OSI_ANIM", "1.0"))

STEP_DELAY = 0.8     # 계층 한 단계마다 쉬는 시간(초)
DOG_DELAY = 0.045    # L1 강아지 애니메이션 프레임 간격(초)
