"""
Passive packet capture engine.
Supports two input modes:
  - Live: sniff on a network interface (never transmits)
  - PCAP: read and analyze a saved .pcap file offline
"""

from scapy.all import sniff, rdpcap, ARP, IP, TCP, UDP, Ether
from scrutics.db.inventory import AssetInventory
from scrutics.classifier.oui import load_oui_db, lookup_vendor, is_ot_vendor
from scrutics.classifier.protocol import classify_by_ports


class CaptureEngine:
    def __init__(self, inventory: AssetInventory, progress_callback=None):
        """
        progress_callback: optional callable(packet_count) for UI updates
        """
        self.inventory = inventory
        self.oui_db = load_oui_db()
        self.progress_callback = progress_callback
        self._packet_count = 0

    def _process_packet(self, pkt):
        """Handle a single captured packet — shared by live and pcap modes."""
        src_mac = None
        src_ip = None
        dst_ip = None
        dst_port = None
        proto = None

        if Ether in pkt:
            src_mac = pkt[Ether].src

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

        if TCP in pkt:
            dst_port = pkt[TCP].dport
            proto = "TCP"
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            proto = "UDP"

        if ARP in pkt:
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

        if not src_ip or not src_mac:
            return
        if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        # Update source device record
        self.inventory.update(
            ip=src_ip,
            mac=src_mac,
            dst_ip=dst_ip,
            dst_port=dst_port
        )

        # Credit destination device with the port it's listening on
        if dst_ip and dst_port and dst_ip not in ("255.255.255.255", "0.0.0.0"):
            self.inventory.credit_listener_port(dst_ip, dst_port)
            dst_asset = self.inventory.get(dst_ip)
            if dst_asset and dst_asset.ports_seen:
                result = classify_by_ports(dst_asset.ports_seen, mac=dst_asset.mac)
                dst_asset.protocols = result["protocols"]
                dst_asset.role = result["role"]
                dst_asset.is_ot = result["is_ot"]
                dst_asset.confidence = result["confidence"]

        # Enrich source with OUI vendor
        asset = self.inventory.get(src_ip)
        if asset and asset.vendor == "Unknown":
            vendor = lookup_vendor(src_mac, self.oui_db)
            asset.vendor = vendor
            asset.is_ot_vendor = is_ot_vendor(vendor)

        # Classify source by ports seen
        if asset and asset.ports_seen:
            result = classify_by_ports(asset.ports_seen, mac=src_mac)
            asset.protocols = result["protocols"]
            asset.role = result["role"]
            asset.is_ot = result["is_ot"]
            asset.confidence = result["confidence"]

        self._packet_count += 1
        if self.progress_callback:
            self.progress_callback(self._packet_count)

    def start_live(self, interface: str, timeout: int = 60, packet_count: int = 0):
        """
        Passive live capture on a network interface.
        timeout: stop after N seconds (0 = run until Ctrl+C)
        packet_count: stop after N packets (0 = unlimited)
        """
        sniff(
            iface=interface,
            prn=self._process_packet,
            store=False,
            count=packet_count,
            timeout=timeout if timeout > 0 else None,
            promisc=True,
        )

    def start_pcap(self, filepath: str):
        """
        Analyze a saved .pcap file offline.
        """
        packets = rdpcap(filepath)
        for pkt in packets:
            self._process_packet(pkt)
