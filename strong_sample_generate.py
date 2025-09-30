from scapy.all import IP, UDP, Ether, Raw, wrpcap
from scapy.layers.inet import TCP

# Create Ethernet+IP+UDP packets (SIP + RTP)
packets = []

# SIP packets (VoIP)
packets.append(Ether()/IP(src="192.0.2.1", dst="192.0.2.2")/UDP(sport=5060,dport=5060)/Raw(load="INVITE sip:user@domain.com SIP/2.0"))
packets.append(Ether()/IP(src="192.0.2.2", dst="192.0.2.1")/UDP(sport=5060,dport=5060)/Raw(load="200 OK SIP/2.0"))

# RTP packets
for i in range(3):
    packets.append(Ether()/IP(src="192.0.2.1", dst="192.0.2.2")/UDP(sport=5004,dport=5004)/Raw(load=f"RTP STREAM {i+1}"))
    packets.append(Ether()/IP(src="192.0.2.2", dst="192.0.2.1")/UDP(sport=5004,dport=5004)/Raw(load=f"RTP STREAM {i+1}"))

# Write to PCAP
wrpcap("strong_sample_fixed.pcap", packets)

print("✅ TShark-compatible PCAP created: strong_sample_fixed.pcap")
