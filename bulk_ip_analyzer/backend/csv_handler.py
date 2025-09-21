# backend/csv_handler.py
import csv
from typing import Iterator, Dict, Any

def parse_csv_file(path: str) -> Iterator[Dict[str, Any]]:
    with open(path, newline='', encoding='utf-8') as cf:
        reader = csv.DictReader(cf)
        for row in reader:
            yield row
