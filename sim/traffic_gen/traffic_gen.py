import time
import random
from scapy.all import IP, TCP, UDP, send, Raw

# Target Map based on your OT/ICS simulation subnet
TARGETS = {
    "modbus": "192.168.100.10",
    "modbus2": "192.168.100.11",
    "enip": "192.168.100.12",
    "bacnet": "192.168.100.13",
}

def send_modbus_noise():
    # Target: Modbus Device 1 or 2
    ip = random.choice([TARGETS["modbus"], TARGETS["modbus2"]])
    packet = IP(dst=ip)/TCP(dport=502)/Raw(load=b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a")
    send(packet, verbose=False)
    print(f"[+] Traffic -> {ip} (Modbus/TCP)")

def send_enip_noise():
    # Target: Rockwell/EtherNet/IP Stub
    packet = IP(dst=TARGETS["enip"])/TCP(dport=44818)/Raw(load=b"\x65\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    send(packet, verbose=False)
    print(f"[+] Traffic -> {TARGETS['enip']} (EtherNet/IP)")

def send_bacnet_noise():
    # Target: BACnet Device
    packet = IP(dst=TARGETS["bacnet"])/UDP(dport=47808)/Raw(load=b"\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08")
    send(packet, verbose=False)
    print(f"[+] Traffic -> {TARGETS['bacnet']} (BACnet/IP)")

if __name__ == "__main__":
    print("OT Traffic Generator active. Generating noise across stubs...")
    while True:
        choice = random.choice([send_modbus_noise, send_enip_noise, send_bacnet_noise])
        choice()
        time.sleep(random.uniform(2, 6))