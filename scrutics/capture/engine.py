"""
Passive packet capture engine.
Listens on a network interface and feeds observed packets
into the asset inventory. Never transmits anything.
"""

from scapy.all import sniff, ARP, IP, TCP, UDP, Ether
from scrutics.db.inventory import AssetInventory
from scrutics.classifier.oui import load_oui_db, lookup_vendor, is_ot_vendor
from scrutics.classifier.protocol import classify_by_ports


class CaptureEngine:
    def __init__(self, interface: str, inventory: AssetInventory):
        self.interface = interface
        self.inventory = inventory
        self.oui_db = load_oui_db()

    def _process_packet(self, pkt):
        """Handle a single captured packet."""
        src_mac = None
        src_ip = None
        dst_ip = None
        dst_port = None

        # Extract MAC
        if Ether in pkt:
            src_mac = pkt[Ether].src

        # Extract IP layer
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

        # Extract destination port
        if TCP in pkt:
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            dst_port = pkt[UDP].dport

        # ARP packets reveal IP-MAC mappings even without IP layer
        if ARP in pkt:
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

        if not src_ip or not src_mac:
            return

        # Skip broadcast/multicast MACs
        if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        # Update inventory
        self.inventory.update(
            ip=src_ip,
            mac=src_mac,
            dst_ip=dst_ip,
            dst_port=dst_port
        )

        # Enrich with OUI vendor if not already done
        asset = self.inventory.get(src_ip)
        if asset and asset.vendor == "Unknown":
            vendor = lookup_vendor(src_mac, self.oui_db)
            asset.vendor = vendor
            asset.is_ot_vendor = is_ot_vendor(vendor)

        # Classify by ports seen so far
        if asset and asset.ports_seen:
            result = classify_by_ports(asset.ports_seen)
            asset.protocols = result["protocols"]
            asset.role = result["role"]
            asset.is_ot = result["is_ot"]
            asset.confidence = result["confidence"]

    def start(self, packet_count: int = 0, timeout: int = None):
        """
        Begin passive capture.
        packet_count=0 means capture indefinitely.
        timeout=N stops after N seconds.
        """
        print(f"[*] Starting passive capture on interface: {self.interface}")
        print("[*] Press Ctrl+C to stop.\n")

        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            count=packet_count,
            timeout=timeout
        )
