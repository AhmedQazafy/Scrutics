"""Suricata EVE JSON parser for Scrutics."""

import json
from typing import Generator


def parse_eve_file(filepath: str) -> Generator[dict, None, None]:
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def extract_flows_from_eve(filepath: str) -> list:
    flows = []
    for event in parse_eve_file(filepath):
        src_ip   = event.get("src_ip")
        dst_ip   = event.get("dest_ip")
        dst_port = event.get("dest_port")
        proto    = event.get("proto", "TCP").upper()
        ts_str   = event.get("timestamp", "")
        etype    = event.get("event_type", "")

        if not src_ip or not dst_ip:
            continue

        ts_float = 0.0
        if ts_str:
            try:
                from datetime import datetime
                ts_clean = ts_str.replace("+0000", "+00:00")
                ts_float = datetime.fromisoformat(ts_clean).timestamp()
            except Exception:
                try:    ts_float = float(ts_str)
                except: ts_float = 0.0

        flow = {"src_ip": src_ip, "src_mac": None, "dst_ip": dst_ip,
                "dst_port": dst_port, "proto": proto,
                "timestamp": ts_float, "source": f"suricata_{etype}"}

        if etype == "alert":
            alert_info = event.get("alert", {})
            flow["alert"] = {
                "signature": alert_info.get("signature", "Unknown"),
                "category":  alert_info.get("category", ""),
                "severity":  alert_info.get("severity", 3),
                "action":    alert_info.get("action", "allowed"),
            }
        if etype == "modbus": flow["dst_port"] = 502;   flow["source"] = "suricata_modbus"
        elif etype == "dnp3": flow["dst_port"] = 20000; flow["source"] = "suricata_dnp3"
        elif etype == "enip": flow["dst_port"] = 44818; flow["source"] = "suricata_enip"

        flows.append(flow)
    return flows
