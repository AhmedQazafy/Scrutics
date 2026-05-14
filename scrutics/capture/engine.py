"""
Passive capture engine. NEVER transmits packets.
All Scapy imports are lazy. Passive enforcement applied before capture.
"""

import time
import datetime
from collections import deque

from scrutics.db.inventory import AssetInventory
from scrutics.baseline.engine import BaselineEngine
from scrutics.baseline.scorer import oui_score, protocol_score, confidence_pct


class CaptureEngine:
    def __init__(self, inventory: AssetInventory, progress_callback=None, baseline_window: int = 60):
        self.inventory = inventory
        self.progress_callback = progress_callback
        self._packet_count = 0
        self._oui_db = None
        self.baseline = BaselineEngine(observation_window=baseline_window)
        self.event_log: deque = deque(maxlen=500)
        self._event_buffer: list = []
        self._logged_protocols: dict = {}   # ip -> frozenset of protocols last logged
        self._logged_dst_ports: dict = {}   # ip -> set of dst ports already logged

    def _log(self, message: str, style: str = "dim white"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        entry = (ts, message, style)
        self.event_log.append(entry)
        self._event_buffer.append(entry)

    def _get_oui_db(self) -> dict:
        if self._oui_db is None:
            from scrutics.classifier.oui import load_oui_db
            self._oui_db = load_oui_db()
        return self._oui_db

    def get_event_buffer(self) -> list:
        return list(self._event_buffer)

    def _process_packet(self, pkt):
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP

        src_mac = src_ip = dst_ip = dst_port = proto = None
        now_ts = time.time()

        if Ether in pkt: src_mac = pkt[Ether].src
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        if TCP in pkt:   dst_port = pkt[TCP].dport; proto = "TCP"
        elif UDP in pkt: dst_port = pkt[UDP].dport; proto = "UDP"
        if ARP in pkt:
            src_ip  = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

        if not src_ip or not src_mac:
            return
        if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        self._process_flow_data(src_ip=src_ip, src_mac=src_mac,
                                dst_ip=dst_ip, dst_port=dst_port,
                                proto=proto, ts=now_ts)

    def _process_flow_data(self, src_ip, src_mac, dst_ip, dst_port, proto, ts, alert=None):
        if not src_ip:
            return

        from scrutics.classifier.oui import lookup_vendor, is_ot_vendor
        from scrutics.classifier.protocol import classify_by_ports

        self.inventory.update(ip=src_ip, mac=src_mac, dst_ip=dst_ip, dst_port=dst_port)

        if dst_ip and dst_port and dst_ip not in ("255.255.255.255", "0.0.0.0"):
            self.inventory.credit_listener_port(dst_ip, dst_port)
            dst_asset = self.inventory.get(dst_ip)
            if dst_asset and dst_asset.ports_seen:
                self._classify_and_score(dst_asset)
                from scrutics.classifier.protocol import ICS_PORTS
                if dst_port in ICS_PORTS:
                    seen = self._logged_dst_ports.setdefault(dst_ip, set())
                    if dst_port not in seen:
                        seen.add(dst_port)
                        self._log(f"{dst_ip} <- port {dst_port} ({proto or '?'}) from {src_ip}", "cyan")

        asset = self.inventory.get(src_ip)
        if asset:
            if asset.vendor == "Unknown" and src_mac:
                vendor = lookup_vendor(src_mac, self._get_oui_db())
                asset.vendor = vendor
                asset.is_ot_vendor = is_ot_vendor(vendor)
                if asset.is_ot_vendor:
                    self._log(f"{src_ip} -> OUI match: {vendor}", "yellow")

            if asset.ports_seen:
                self._classify_and_score(asset)

            anomaly = self.baseline.observe(
                ip=src_ip, timestamp=ts,
                initiates=asset.initiates,
                peers=set(asset.peer_ips),
            )
            asset.behavioral_score     = self.baseline.get_behavioral_score(src_ip)
            asset.directionality_score = self.baseline.get_directionality_score(src_ip)
            asset.baseline_status      = self.baseline.get_status(src_ip)
            self._recompute_confidence(asset)

            if anomaly:
                sev = anomaly.get("severity", "MEDIUM")
                style = "bold red" if sev == "HIGH" else "yellow"
                self._log(f"! {src_ip} [{anomaly['type']}] {anomaly['detail']}", style)

        if alert:
            sev_map = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
            sev = sev_map.get(alert.get("severity", 3), "MEDIUM")
            self.baseline.anomaly_log.append({
                "ip": src_ip, "timestamp": ts, "type": "SURICATA_ALERT",
                "detail": f"{alert.get('signature','?')} [{alert.get('category','')}]",
                "severity": sev,
            })
            self._log(f"! SURICATA {src_ip} -- {alert.get('signature','?')}",
                      "bold red" if sev == "HIGH" else "yellow")

        self._packet_count += 1
        if self.progress_callback:
            self.progress_callback(self._packet_count)

    def _classify_and_score(self, asset):
        from scrutics.classifier.protocol import classify_by_ports
        result = classify_by_ports(asset.ports_seen, mac=asset.mac)
        asset.protocols = result["protocols"]
        asset.role      = result["role"]
        asset.is_ot     = result["is_ot"]
        asset.confidence = result["confidence"]
        asset.oui_score      = oui_score(asset.is_ot_vendor)
        asset.protocol_score = protocol_score(
            matched_ics=result["is_ot"] is True,
            matched_it=result["is_ot"] is False,
        )
        self._recompute_confidence(asset)
        if result["is_ot"] is True and result.get("matched_rule"):
            current = frozenset(asset.protocols)
            if self._logged_protocols.get(asset.ip) != current:
                self._logged_protocols[asset.ip] = current
                self._log(f"{asset.ip} -> {', '.join(asset.protocols)} ({result['matched_rule']})", "green")

    def _recompute_confidence(self, asset):
        asset.confidence_pct = confidence_pct(
            oui_s=asset.oui_score, protocol_s=asset.protocol_score,
            behavioral_s=asset.behavioral_score, directional_s=asset.directionality_score,
        )

    def start_live(self, interface: str, timeout: int = 60, packet_count: int = 0):
        from scrutics.passive import enforce_passive, verify_passive
        enforce_passive()
        violations = verify_passive()
        if violations:
            raise RuntimeError(f"Passive enforcement compromised: {violations}")
        from scapy.all import sniff
        self._log(f"Passive capture started on {interface}", "cyan")
        sniff(iface=interface, prn=self._process_packet, store=False,
              count=packet_count, timeout=timeout if timeout > 0 else None, promisc=True)
        self._log("Capture complete", "dim white")

    def start_pcap(self, filepath: str):
        from scrutics.passive import enforce_passive
        enforce_passive()
        from scapy.all import rdpcap
        self._log(f"Loading PCAP: {filepath}", "cyan")
        packets = rdpcap(filepath)
        self._log(f"Processing {len(packets)} packets", "dim white")
        for pkt in packets:
            self._process_packet(pkt)

    def start_zeek(self, filepath: str):
        from scrutics.parsers.zeek import extract_flows_from_zeek
        flows = extract_flows_from_zeek(filepath)
        self._log(f"Loaded {len(flows)} flows from Zeek log", "cyan")
        for flow in flows:
            self._process_flow(flow)

    def start_suricata(self, filepath: str):
        from scrutics.parsers.suricata import extract_flows_from_eve
        flows = extract_flows_from_eve(filepath)
        alert_count = sum(1 for f in flows if "alert" in f)
        self._log(f"Loaded {len(flows)} events ({alert_count} alerts) from EVE", "cyan")
        for flow in flows:
            self._process_flow(flow)

    def start_file(self, filepath: str):
        from scrutics.parsers.detector import detect_file_type
        ftype = detect_file_type(filepath)
        self._log(f"File type: {ftype}", "dim white")
        if ftype in ("pcap", "pcapng"): self.start_pcap(filepath)
        elif ftype == "zeek":           self.start_zeek(filepath)
        elif ftype == "suricata":       self.start_suricata(filepath)
        else:
            self._log(f"Unsupported format: {filepath}", "bold red")
            raise ValueError(f"Cannot parse: {filepath}")

    def _process_flow(self, flow: dict):
        self._process_flow_data(
            src_ip=flow.get("src_ip"), src_mac=flow.get("src_mac"),
            dst_ip=flow.get("dst_ip"), dst_port=flow.get("dst_port"),
            proto=flow.get("proto", "TCP"), ts=flow.get("timestamp", time.time()),
            alert=flow.get("alert"),
        )
