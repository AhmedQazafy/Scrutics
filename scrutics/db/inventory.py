"""In-memory asset inventory with multi-factor confidence scoring."""

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
    oui_score: int = 0
    protocol_score: int = 0
    behavioral_score: int = 0
    directionality_score: int = 0
    confidence_pct: int = 0
    baseline_status: str = "no_data"
    packet_count: int = 0
    peer_ips: set = field(default_factory=set)
    initiates: bool = False
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict:
        proto_str = ", ".join(self.protocols) if self.protocols else "Unknown"
        type_str  = "OT" if self.is_ot is True else "IT" if self.is_ot is False else "Unknown"
        left = {
            "ip": self.ip, "mac": self.mac, "vendor": self.vendor,
            "protocol": proto_str, "role": self.role,
            "confidence_pct": self.confidence_pct, "type": type_str,
        }
        right = {
            "oui_score": self.oui_score, "protocol_score": self.protocol_score,
            "behavioral_score": self.behavioral_score, "directionality_score": self.directionality_score,
            "baseline_status": self.baseline_status, "packet_count": self.packet_count,
            "peer_count": len(self.peer_ips),
            "ports_seen": "|".join(str(p) for p in sorted(self.ports_seen)),
            "initiates": self.initiates, "is_ot_vendor": self.is_ot_vendor,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        }
        return {**left, **right}


class AssetInventory:
    def __init__(self):
        self._assets: dict = {}

    def update(self, ip: str, mac: str = None, dst_ip: str = None, dst_port: int = None):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if ip not in self._assets:
            self._assets[ip] = Asset(ip=ip, mac=mac or "Unknown", first_seen=now)
        elif mac:
            self._assets[ip].mac = mac
        asset = self._assets[ip]
        asset.last_seen = now
        asset.packet_count += 1
        if dst_ip and dst_ip not in ("255.255.255.255", "0.0.0.0"):
            asset.peer_ips.add(dst_ip)
            asset.initiates = True
        if dst_port:
            asset.ports_seen.add(dst_port)

    def credit_listener_port(self, ip: str, port: int):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if ip not in self._assets:
            self._assets[ip] = Asset(ip=ip, mac="Unknown", first_seen=now)
        self._assets[ip].ports_seen.add(port)

    def get_all(self) -> list:
        return list(self._assets.values())

    def get(self, ip: str) -> Optional[Asset]:
        return self._assets.get(ip)

    def count(self) -> int:
        return len(self._assets)

    def export_csv(self, path: str):
        assets = self.get_all()
        if not assets:
            return
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=assets[0].to_dict().keys())
            writer.writeheader()
            for asset in assets:
                writer.writerow(asset.to_dict())
