import socket
import time
import random

DEVICES = {
    "modbus1": ("192.168.100.10", 502),
    "modbus2": ("192.168.100.11", 502),
    "enip":    ("192.168.100.12", 44818),
    "bacnet":  ("192.168.100.13", 47808),
}

def poll_device(host, port, proto="TCP"):
    try:
        if proto == "TCP":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host, port))
            s.close()
            print(f"[+] TCP connect to {host}:{port}", flush=True)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"\x00\x01", (host, port))
            s.close()
            print(f"[+] UDP send to {host}:{port}", flush=True)
    except Exception as e:
        print(f"[-] {host}:{port} failed: {e}", flush=True)

if __name__ == "__main__":
    print("[*] Traffic generator started — waiting 15s for devices to boot...", flush=True)
    time.sleep(15)
    print("[*] Starting polling loop", flush=True)
    while True:
        poll_device("192.168.100.10", 502)
        poll_device("192.168.100.11", 502)
        poll_device("192.168.100.12", 44818)
        poll_device("192.168.100.13", 47808, proto="UDP")
        time.sleep(random.uniform(2, 5))
