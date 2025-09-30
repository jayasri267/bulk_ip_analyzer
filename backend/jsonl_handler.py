# backend/jsonl_handler.py
import json
from typing import Iterator, Dict, Any

def parse_jsonl_file(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue
