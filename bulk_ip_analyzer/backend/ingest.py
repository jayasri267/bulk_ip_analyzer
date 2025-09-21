# backend/ingest.py
import os
from typing import Iterator, Dict, Any
from .pcap_parser import parse_pcap_file
from .jsonl_handler import parse_jsonl_file
from .csv_handler import parse_csv_file

def detect_and_parse(path: str) -> Iterator[Dict[str, Any]]:
    _, ext = os.path.splitext(path.lower())
    if ext in ('.pcap', '.pcapng'):
        yield from parse_pcap_file(path)
    elif ext in ('.jsonl', '.ndjson'):
        yield from parse_jsonl_file(path)
    elif ext == '.json':
        try:
            import json
            with open(path, 'r', encoding='utf-8') as f:
                first = f.read(2)
                f.seek(0)
                if first.startswith('['):
                    data = json.load(f)
                    for obj in data:
                        yield obj
                else:
                    yield from parse_jsonl_file(path)
        except Exception:
            yield from parse_jsonl_file(path)
    elif ext == '.csv':
        yield from parse_csv_file(path)
    else:
        try:
            yield from parse_jsonl_file(path)
        except Exception:
            yield from parse_csv_file(path)
