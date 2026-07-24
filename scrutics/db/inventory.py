"""In-memory asset inventory with multi-factor confidence scoring."""

from dataclasses import dataclass, field
from typing import Optional
import csv
import datetime
import ipaddress


def is_inventory_ip(
    ip: str | None,
    *,
    include_public_ips: bool = False,
    cidrs: list[ipaddress.IPv4Network] | None = None,
) -> bool:
    """
    Return True for device IPs that should appear in inventory.

    Broadcast, multicast, unspecified, and subnet-broadcast-looking .255
    addresses are traffic targets, not assets.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    if addr.is_unspecified or addr.is_multicast:
        return False
    if addr.is_loopback or addr.is_reserved:
        return False
    if ip == "255.255.255.255":
        return False
    if ip.rsplit(".", 1)[-1] == "255":
        return False
    if cidrs:
        return any(addr in network for network in cidrs)
    if not include_public_ips and not (addr.is_private or addr.is_link_local):
        return False
    return True


@dataclass
class Asset:
    ip: str
    mac: str
    vendor: str = "Unknown"
    is_ot_vendor: bool = False
    protocols: list = field(default_factory=list)
    ports_seen: set = field(default_factory=set)
    contacted_ports: set = field(default_factory=set)
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
    behavioral_constraints: dict = field(default_factory=dict)
    peer_first_seen: dict = field(default_factory=dict)   # peer_ip -> epoch float
    _constraint_anomaly_ts: dict = field(default_factory=dict)  # type -> epoch float

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
            "contacted_ports": "|".join(str(p) for p in sorted(self.contacted_ports)),
            "initiates": self.initiates, "is_ot_vendor": self.is_ot_vendor,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        }
        return {**left, **right}


class AssetInventory:
    def __init__(self, inventory_config: dict | None = None):
        self._assets: dict = {}
        if inventory_config is None:
            try:
                from scrutics.config.loader import load_inventory_config
                inventory_config = load_inventory_config()
            except Exception:
                inventory_config = {}
        self._include_public_ips = bool(inventory_config.get("include_public_ips", False))
        self._cidrs = []
        for cidr in inventory_config.get("cidrs", []) or []:
            self._cidrs.append(ipaddress.ip_network(str(cidr), strict=False))

    def is_asset_ip(self, ip: str | None) -> bool:
        return is_inventory_ip(
            ip,
            include_public_ips=self._include_public_ips,
            cidrs=self._cidrs,
        )

    def update(self, ip: str, mac: str = None, dst_ip: str = None, dst_port: int = None):
        if not self.is_asset_ip(ip):
            return
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if ip not in self._assets:
            self._assets[ip] = Asset(ip=ip, mac=mac or "Unknown", first_seen=now)
        elif mac:
            self._assets[ip].mac = mac
        asset = self._assets[ip]
        asset.last_seen = now
        asset.packet_count += 1
        if self.is_asset_ip(dst_ip):
            asset.peer_ips.add(dst_ip)
            asset.initiates = True
        if dst_port:
            asset.contacted_ports.add(dst_port)

    def credit_listener_port(self, ip: str, port: int):
        if not self.is_asset_ip(ip) or not port:
            return
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
