# backend/tor_detector.py
import requests

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_cached_tor = None

def _load_tor_list():
    global _cached_tor
    if _cached_tor is None:
        try:
            r = requests.get(TOR_EXIT_LIST_URL, timeout=10)
            lines = r.text.splitlines()
            _cached_tor = set([l.strip() for l in lines if l and not l.startswith('#')])
        except Exception:
            _cached_tor = set()
    return _cached_tor

def is_tor(ip: str) -> bool:
    try:
        tor = _load_tor_list()
        return ip in tor
    except Exception:
        return False
