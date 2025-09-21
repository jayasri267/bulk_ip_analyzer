# backend/app.py
from typing import Iterable, Dict, Any
import pandas as pd
from .classify import enrich_and_classify_record

def analyze_records(records: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    """
    Takes an iterable/generator of records (from pcap/jsonl/csv),
    runs enrichment/classification and returns a pandas DataFrame.
    """
    enriched = []
    for rec in records:
        try:
            er = enrich_and_classify_record(rec)
            enriched.append(er)
        except Exception:
            continue
    if not enriched:
        return pd.DataFrame()
    return pd.DataFrame(enriched)
