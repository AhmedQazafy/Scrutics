"""
In-memory asset inventory.
Stores and updates device records as packets are observed.
"""

from dataclasses import dataclass, field
from typing import Optional
import csv
import datetime


@dataclass
class Asset:
    ip: str
    mac: str
    vendor: str = "Unknown"
    is_ot_vendor: bool = False
    protocols: list = field(default_factory=list)
    ports_seen: set = field(default_factory=set)
    role: str = "Unclassified"
    is_ot: Optional[bool] = None
    confidence: str = "LOW"
    packet_count: int = 0
    peer_ips: set = field(default_factory=set)
    initiates: bool = False
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "is_ot_vendor": self.is_ot_vendor,
            "protocols": ", ".join(self.protocols) if self.protocols else "Unknown",
            "role": self.role,
            "is_ot": self.is_ot,
            "confidence": self.confidence,
            "packet_count": self.packet_count,
            "peer_count": len(self.peer_ips),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class AssetInventory:
    def __init__(self):
        self._assets: dict[str, Asset] = {}  # keyed by IP

    def update(self, ip: str, mac: str, dst_ip: str = None, dst_port: int = None):
        """Update or create an asset record from a single observed packet."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if ip not in self._assets:
            self._assets[ip] = Asset(ip=ip, mac=mac, first_seen=now)

        asset = self._assets[ip]
        asset.last_seen = now
        asset.packet_count += 1

        if dst_ip and dst_ip not in ("255.255.255.255", "0.0.0.0"):
            asset.peer_ips.add(dst_ip)
            asset.initiates = True

        if dst_port:
            asset.ports_seen.add(dst_port)

    def get_all(self) -> list[Asset]:
        return list(self._assets.values())

    def get(self, ip: str) -> Optional[Asset]:
        return self._assets.get(ip)

    def count(self) -> int:
        return len(self._assets)

    def export_csv(self, path: str):
        """Export asset inventory to CSV."""
        assets = self.get_all()
        if not assets:
            print("[!] No assets to export.")
            return

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=assets[0].to_dict().keys())
            writer.writeheader()
            for asset in assets:
                writer.writerow(asset.to_dict())

        print(f"[+] Exported {len(assets)} assets to {path}")
