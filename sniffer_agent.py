# sniffer_agent.py
from scapy.all import sniff, IP, TCP, UDP
import requests
import json
import time
import sys

# CONFIGURATION
# If running Server and Agent on the SAME machine: use "http://127.0.0.1:5000/analyze"
# If running Agent on Raspberry Pi and Server on Laptop: use "http://[LAPTOP_IP]:5000/analyze"
API_URL = "http://127.0.0.1:5000/analyze" 

# PACKET COUNTER
packet_count = 0

def process_packet(packet):
    global packet_count
    
    # We only care about IP packets (ignore ARP, raw ethernet, etc.)
    if IP in packet:
        try:
            # 1. EXTRACT FEATURES
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_len = len(packet)
            
            # Default to 0 if protocol not found
            src_port = 0
            dst_port = 0
            protocol = 0
            
            # Check for TCP
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = 6 # TCP Protocol Number
            # Check for UDP
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = 17 # UDP Protocol Number
            
            # Skip packets if we couldn't identify port (ICMP etc)
            if protocol == 0:
                return

            # 2. PREPARE PAYLOAD
            # Matches the format expected by app.py
            feature_payload = {
                "src_ip": src_ip,
                "src_port": src_port, 
                "dst_port": dst_port, 
                "proto": protocol, 
                "pkt_len": packet_len
            }

            # 3. SEND TO API SERVER
            # meaningful print to show activity
            print(f"[{packet_count}] Sending Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

            response = requests.post("http://127.0.0.1:5000/analyze", json=feature_payload, timeout=2)
            # 4. DISPLAY RESULT
            if response.status_code == 200:
                result = response.json()
                if result['prediction'] == "Malicious":
                    print(f"🚨 ALERT! Malicious Traffic Detected! Confidence: {result['confidence']:.2f}")
                else:
                    print(f"✅ Normal Traffic")
            
            packet_count += 1

        except Exception as e:
            # Often happens if API is down or network is busy
            print(f"Error processing packet: {e}")

# MAIN LOOP
print("Starting Network Sniffer...")
print(f"Sending data to: {"http://127.0.0.1:5000/analyze"}")
print("Press CTRL+C to stop.")

# 'count=0' means sniff infinitely
# 'store=0' means don't keep packets in RAM (prevents crashing)
try: 
    sniff(filter="ip", prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\nSniffer stopped.")
    sys.exit()