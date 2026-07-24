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
        self._logged_protocols: dict = {}   # ip -> frozenset of protocols last logged
        self._logged_dst_ports: dict = {}   # ip -> set of dst ports already logged
        self.writer      = None   # RollingWriter — attached by caller before capture
        self.sink_manager = None  # SinkManager   — attached by caller before capture
        self.no_baseline  = False  # skip anomaly detection (e.g. large PCAP files)
        self._get_oui_db()         # preload at startup — avoids silent delay on first packet

    def _log(self, message: str, style: str = "dim white"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        entry = (ts, message, style)
        self.event_log.append(entry)
        if self.writer:
            self.writer.write_event(ts, message)

    def _get_oui_db(self) -> dict:
        if self._oui_db is None:
            from scrutics.classifier.oui import load_oui_db
            self._oui_db = load_oui_db()
        return self._oui_db

    def get_event_buffer(self) -> list:
        """
        Deprecated compatibility shim.

        Events are now persisted immediately by RollingWriter. This returns
        only the current in-memory display buffer.
        """
        return list(self.event_log)

    def _process_packet(self, pkt):
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.inet import IP, TCP, UDP

        src_mac = src_ip = dst_ip = src_port = dst_port = proto = None
        now_ts = float(getattr(pkt, "time", time.time()))

        if Ether in pkt: src_mac = pkt[Ether].src
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "TCP"
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "UDP"
        if ARP in pkt:
            src_ip  = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

        if not src_ip or not src_mac:
            return
        if not self.inventory.is_asset_ip(src_ip):
            return
        if src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        self._process_flow_data(src_ip=src_ip, src_mac=src_mac,
                                dst_ip=dst_ip, src_port=src_port,
                                dst_port=dst_port, proto=proto, ts=now_ts,
                                trust_dst_port=False)

    def _process_flow_data(self, src_ip, src_mac, dst_ip, dst_port, proto, ts,
                           src_port=None, alert=None, trust_dst_port=True):
        if not self.inventory.is_asset_ip(src_ip):
            return
        if not self.inventory.is_asset_ip(dst_ip):
            dst_ip = None

        from scrutics.classifier.oui import lookup_vendor, is_ot_vendor
        from scrutics.classifier.protocol import classify_by_ports, known_service_ports

        self.inventory.update(ip=src_ip, mac=src_mac, dst_ip=dst_ip, dst_port=dst_port)
        service_ports = known_service_ports()

        if src_port in service_ports:
            self.inventory.credit_listener_port(src_ip, src_port)

        if dst_ip and dst_port and (trust_dst_port or dst_port in service_ports):
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

            self._check_behavioral_constraints(asset, dst_ip, dst_port, ts)

            if not self.no_baseline:
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
                    if self.writer:
                        self.writer.write_anomaly(anomaly)
                    if self.sink_manager:
                        self.sink_manager.emit_anomaly(anomaly)

        if alert:
            sev_map = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
            sev = sev_map.get(alert.get("severity", 3), "MEDIUM")
            alert_entry = {
                "ip": src_ip, "timestamp": ts, "type": "SURICATA_ALERT",
                "detail": f"{alert.get('signature','?')} [{alert.get('category','')}]",
                "severity": sev,
            }
            self.baseline.anomaly_log.append(alert_entry)
            self._log(f"! SURICATA {src_ip} -- {alert.get('signature','?')}",
                      "bold red" if sev == "HIGH" else "yellow")
            if self.writer:
                self.writer.write_anomaly(alert_entry)
            if self.sink_manager:
                self.sink_manager.emit_anomaly(alert_entry)

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
        if result.get("behavioral_constraints"):
            asset.behavioral_constraints = result["behavioral_constraints"]
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

    def _check_behavioral_constraints(self, asset, dst_ip, dst_port, ts):
        """
        Check rule-defined behavioral constraints against observed traffic.
        Fires BEHAVIORAL_VIOLATION anomalies — always HIGH severity.
        Independent of baseline window: fires from the first packet.
        """
        c = asset.behavioral_constraints
        if not c:
            return

        def _allowed(vtype, cooldown=60):
            last = asset._constraint_anomaly_ts.get(vtype)
            if last is not None and (ts - last) < cooldown:
                return False
            asset._constraint_anomaly_ts[vtype] = ts
            return True

        def _emit(vtype, detail):
            anomaly = {
                "ip": asset.ip, "timestamp": ts,
                "type": "BEHAVIORAL_VIOLATION",
                "severity": "HIGH",
                "detail": f"[{vtype}] {detail}",
            }
            self.baseline.anomaly_log.append(anomaly)
            self._log(f"! VIOLATION {asset.ip} [{vtype}] {detail}", "bold red")
            if self.writer:
                self.writer.write_anomaly(anomaly)
            if self.sink_manager:
                self.sink_manager.emit_anomaly(anomaly)

        # never_initiates — device should only respond, never initiate
        if c.get("never_initiates") and asset.initiates:
            if _allowed("NEVER_INITIATES"):
                _emit("NEVER_INITIATES",
                      f"device initiated connection to {dst_ip}:{dst_port}")

        # allowed_peers — device may only communicate with listed IPs
        allowed_peers = c.get("allowed_peers", [])
        if allowed_peers and dst_ip and dst_ip not in allowed_peers:
            key = f"PEER_{dst_ip}"
            if _allowed(key, cooldown=300):
                _emit("DISALLOWED_PEER",
                      f"communicated with {dst_ip} (not in allowed_peers)")

        # allowed_ports — device should only be seen on listed listener ports
        allowed_ports = c.get("allowed_ports", [])
        if allowed_ports and dst_port and dst_port not in allowed_ports:
            key = f"PORT_{dst_port}"
            if _allowed(key, cooldown=300):
                _emit("DISALLOWED_PORT",
                      f"traffic on port {dst_port} (not in allowed_ports)")

        # alert_on_new_port — alert whenever device appears on a port not seen before
        if c.get("alert_on_new_port") and dst_port:
            known = asset._constraint_anomaly_ts.get("_known_ports", set())
            if dst_port not in known:
                known.add(dst_port)
                asset._constraint_anomaly_ts["_known_ports"] = known
                if len(known) > 1:   # skip the very first port — it's expected
                    _emit("NEW_PORT",
                          f"device active on new port {dst_port}")

        # max_new_peers_per_hour — rate limit new peer discovery
        max_peers = c.get("max_new_peers_per_hour")
        if max_peers and dst_ip:
            if dst_ip not in asset.peer_first_seen:
                asset.peer_first_seen[dst_ip] = ts
            cutoff = ts - 3600
            recent_new = sum(1 for t in asset.peer_first_seen.values() if t >= cutoff)
            if recent_new > max_peers:
                if _allowed("PEER_RATE", cooldown=300):
                    _emit("PEER_RATE_EXCEEDED",
                          f"{recent_new} new peers in last hour (limit: {max_peers})")

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
        from scapy.all import PcapReader
        self._log(f"Streaming PCAP: {filepath}", "cyan")
        count = 0
        with PcapReader(filepath) as packets:
            for pkt in packets:
                self._process_packet(pkt)
                count += 1
        self._log(f"Processed {count} packets", "dim white")

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
