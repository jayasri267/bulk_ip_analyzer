import os
import csv
import json
from scapy.all import IP, UDP, Ether, Raw, wrpcap
import zipfile

# Create demo folder
demo_dir = "bulk_ip_demo"
os.makedirs(demo_dir, exist_ok=True)

# 1️⃣ CSV file
csv_file = os.path.join(demo_dir, "strong_input_ips.csv")
csv_rows = [
    ["ip","src","destination_ip","host"],
    ["8.8.8.8","8.8.8.8","1.1.1.1","google-dns"],
    ["1.1.1.1","1.1.1.1","8.8.8.8","cloudflare"],
    ["208.67.222.222","208.67.222.222","8.8.8.8","opendns"],
    ["185.220.101.0","185.220.101.0","8.8.8.8","tor-exit-node"],
    ["104.244.42.65","104.244.42.65","1.1.1.1","twitter"],
    ["51.15.123.12","51.15.123.12","8.8.8.8","vpn-server"],
    ["89.248.168.10","89.248.168.10","8.8.8.8","proxy-node"],
    ["195.154.161.50","195.154.161.50","1.1.1.1","voip-server"]
]
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerows(csv_rows)

# 2️⃣ JSONL file
jsonl_file = os.path.join(demo_dir, "strong_input.jsonl")
jsonl_rows = [
    {"ip": "8.8.8.8", "host": "google-dns"},
    {"ip": "1.1.1.1", "host": "cloudflare"},
    {"ip": "208.67.222.222", "host": "opendns"},
    {"ip": "185.220.101.0", "host": "tor-exit-node"},
    {"ip": "104.244.42.65", "host": "twitter"},
    {"ip": "51.15.123.12", "host": "vpn-server"},
    {"ip": "89.248.168.10", "host": "proxy-node"},
    {"ip": "195.154.161.50", "host": "voip-server"}
]
with open(jsonl_file, "w") as f:
    for row in jsonl_rows:
        f.write(json.dumps(row) + "\n")

# 3️⃣ Synthetic PCAP (Ethernet headers included)
pcap_file = os.path.join(demo_dir, "strong_sample_fixed.pcap")
packets = [
    Ether()/IP(src="192.0.2.1", dst="192.0.2.2")/UDP(sport=5060,dport=5060)/Raw(load="INVITE sip:user@domain.com SIP/2.0"),
    Ether()/IP(src="192.0.2.2", dst="192.0.2.1")/UDP(sport=5060,dport=5060)/Raw(load="200 OK SIP/2.0"),
    Ether()/IP(src="192.0.2.1", dst="192.0.2.2")/UDP(sport=5004,dport=5004)/Raw(load="RTP STREAM 1"),
    Ether()/IP(src="192.0.2.2", dst="192.0.2.1")/UDP(sport=5004,dport=5004)/Raw(load="RTP STREAM 2")
]
wrpcap(pcap_file, packets)

# 4️⃣ run.sh script
run_sh = os.path.join(demo_dir, "run.sh")
with open(run_sh, "w") as f:
    f.write("""#!/bin/bash
PYTHONPATH=$(pwd) streamlit run frontend/main.py --server.headless false
""")
os.chmod(run_sh, 0o755)

# 5️⃣ Create ZIP
zip_name = "bulk_ip_demo.zip"
with zipfile.ZipFile(zip_name, "w") as zipf:
    for root, dirs, files in os.walk(demo_dir):
        for file in files:
            zipf.write(os.path.join(root, file), arcname=file)

print(f"✅ Demo ZIP created: {zip_name}")
print(f"Files inside: {os.listdir(demo_dir)}")
