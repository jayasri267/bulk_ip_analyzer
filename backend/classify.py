# backend/classify.py
from typing import Dict, Any
from .enrichment import get_geo_info
from .tor_detector import is_tor
from .vpn_proxy_detector import is_vpn_proxy
from .voip_detector import is_voip

def enrich_and_classify_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches a record with GeoIP, Tor, VPN/Proxy, and VoIP info.
    """
    out = dict(rec)
    # try common IP fields
    ip = rec.get('ip') or rec.get('src') or rec.get('src_ip') or rec.get('caller') or rec.get('caller_ip') or rec.get('host') or rec.get('destination_ip')
    
    if ip:
        try:
            geo = get_geo_info(ip)
            out.update(geo)
        except Exception:
            pass
        try:
            out['Tor'] = bool(is_tor(ip))
        except Exception:
            out['Tor'] = False
        try:
            out['VPN/Proxy'] = bool(is_vpn_proxy(ip))
        except Exception:
            out['VPN/Proxy'] = False
        try:
            out['VoIP'] = bool(is_voip(ip))
        except Exception:
            out['VoIP'] = False
    else:
        out['Tor'] = False
        out['VPN/Proxy'] = False
        out['VoIP'] = False

    return out
