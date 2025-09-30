# Bulk IP Analysis — Prototype


## Overview


A prototype to ingest PCAP / JSONL / CSV / uploaded files and run enrichment & classification (GeoIP, Tor, VPN/Proxy, VoIP heuristics). Optimized for PCAP + JSONL.


## Requirements


- Linux (Kali/Ubuntu recommended)
- Python 3.10+
- `tshark` (for pyshark to parse PCAPs)


Install system deps:


```bash
sudo apt update
sudo apt install -y tshark
# Bulk_IP_Analyzer
