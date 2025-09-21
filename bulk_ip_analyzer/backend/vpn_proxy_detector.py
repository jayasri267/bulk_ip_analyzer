# backend/vpn_proxy_detector.py
import requests

VPNAPI_URL = "https://vpnapi.io/api/{ip}?key="

def is_vpn_proxy(ip: str) -> bool:
    try:
        r = requests.get(VPNAPI_URL.format(ip=ip), timeout=8)
        data = r.json()
        sec = data.get('security', {})
        return bool(sec.get('vpn') or sec.get('proxy') or sec.get('tor'))
    except Exception:
        return False
