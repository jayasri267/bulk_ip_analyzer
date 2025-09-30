# backend/pcap_parser.py
import pyshark
from typing import Iterator, Dict, Any
import os

def parse_pcap_file(path: str) -> Iterator[Dict[str, Any]]:
    """
    Parse a PCAP using pyshark and yield call/session dictionaries.
    Streaming mode: keep_packets=False to reduce memory.
    """
    if not os.path.exists(path):
        return

    cap = pyshark.FileCapture(path, keep_packets=False)
    calls = {}

    for pkt in cap:
        try:
            layers = [l.layer_name for l in pkt.layers]

            if 'sip' in layers:
                sip = pkt.get_multiple_layers('sip')[0]
                call_id = getattr(sip, 'call_id', None) or getattr(sip, 'Call_ID', None)
                src = pkt.ip.src if hasattr(pkt, 'ip') else None
                dst = pkt.ip.dst if hasattr(pkt, 'ip') else None
                ts = float(pkt.sniff_timestamp)
                cid = call_id or f"sip-{src}-{dst}-{ts}"
                entry = calls.setdefault(cid, {
                    "call_id": cid,
                    "sips": [],
                    "rtp_streams": [],
                    "start_time": ts,
                    "end_time": ts
                })
                entry['sips'].append({
                    'time': ts,
                    'src': src,
                    'dst': dst,
                    'method': getattr(sip, 'Method', getattr(sip, 'method', None)),
                    'raw': str(sip)
                })
                if ts > entry['end_time']:
                    entry['end_time'] = ts

            if 'rtp' in layers or 'rtp_mpeg4_gdp' in layers:
                src = pkt.ip.src if hasattr(pkt, 'ip') else None
                dst = pkt.ip.dst if hasattr(pkt, 'ip') else None
                udp = getattr(pkt, 'udp', None)
                srcport = getattr(udp, 'srcport', None) if udp else None
                dstport = getattr(udp, 'dstport', None) if udp else None
                rtp_layer = pkt.get_multiple_layers('rtp')[0] if 'rtp' in layers else None
                ssrc = getattr(rtp_layer, 'ssrc', None) if rtp_layer else None
                ts = float(pkt.sniff_timestamp)
                entry = {
                    'src_ip': src,
                    'dst_ip': dst,
                    'src_port': srcport,
                    'dst_port': dstport,
                    'ssrc': ssrc,
                    'timestamp': ts
                }
                closest = None
                for c in calls.values():
                    if c['start_time'] - 5 <= ts <= c.get('end_time', c['start_time']) + 120:
                        closest = c
                        break
                if closest is not None:
                    closest['rtp_streams'].append(entry)
        except Exception:
            continue

    for c in calls.values():
        yield {'type': 'call', **c}


