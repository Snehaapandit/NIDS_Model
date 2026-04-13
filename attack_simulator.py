# attack_simulator.py
from scapy.all import IP, TCP, send
import random
import time

target_ip = "127.0.0.1"  # Or the IP of your Sniffer Agent

print(f"Simulating Attack on {target_ip}...")
print("Press CTRL+C to stop.")

try:
    while True:
        # Simulate Mirai Botnet scanning for Telnet (Port 23)
        # Random Source Port (attacker uses random ports)
        # Fixed Dest Port 23 (Telnet - highly suspicious)
        packet = IP(dst=target_ip)/TCP(sport=random.randint(1024,65535), dport=23, flags="S")
        
        send(packet, verbose=0)
        print(f"Sent Malicious Packet -> Port 23")
        
        time.sleep(1) # Send one every second
except KeyboardInterrupt:
    print("Attack stopped.")