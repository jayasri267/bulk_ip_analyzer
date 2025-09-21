# backend/voip_detector.py
import socket

COMMON_SIP_PORTS = [5060, 5061]

def is_voip(ip: str, timeout: float = 0.8) -> bool:
    """Try to detect open SIP ports. This is heuristic and may be blocked by firewalls."""
    for p in COMMON_SIP_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, p))
            s.close()
            return True
        except Exception:
            continue
    return False
